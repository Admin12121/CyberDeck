"use client";

import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";
import { Play, RefreshCw, Square, Settings2, Info, MonitorDot, FolderOpen } from "lucide-react";
import { Router } from "@lucasmarkes/hairline/react";
import { Button } from "@/components/ui/button";
import { Chip, EmptyState, Select, TextInput, ToolButton, WorkspaceTabs } from "@ds/panes";
import { PacketTable } from "./PacketTable";
import { AuthorizedCaseAction } from "@/app/_components/AuthorizedCaseAction";
import { PacketPaneSplit } from "./PacketPaneSplit";
import { CaptureActivity, type CaptureActivityPoint } from "./CaptureActivity";
import { nativeCapturePacketRow } from "./packet-row-model";
import {
  isDesktop, networkRuntimeCapabilitiesV1, captureInterfacesV1, captureStartV1, captureStatusV1, captureStopV1, captureSaveV1,
  type CaptureSaveReceiptV1,
  captureProvenanceV1, captureHostsV1, captureFlowsV1, captureFramePageV1,
  capturePacketDetailsV1, captureFollowStreamV1,
  type CaptureInterfaceV1, type CaptureStatusV1, type CapturePageV1,
  type CaptureFrameProvenanceV1, type CaptureHostV1, type CaptureFlowV1,
  type CaptureFramePageV1, type PcapPacketWire, type StreamTranscriptWire,
} from "@lib/ipc";
import { useWorkbenchCase } from "@state/workbench";
import { useWorkspaceDraft } from "@state/workspace-sessions";
import { activeCaptureId, boundedPageOffset, captureLimits, captureInterfaceEligible, matchesCaptureIdentity } from "./capture-view-policy";
import { currentNativeSession, dropNativeSession, rememberNativeSession, subscribeNativeSessions } from "./capture-session-registry";

type DataTab = "packets" | "hosts" | "flows";
type Tab = DataTab | "statistics";
type SessionRef = { id: number; revision: number };
type Pages = {
  packets: CapturePageV1<CaptureFrameProvenanceV1>;
  hosts: CapturePageV1<CaptureHostV1>;
  flows: CapturePageV1<CaptureFlowV1>;
};
const SIZE = 100;
function emptyPage<T>(): CapturePageV1<T> { return { total: 0, offset: 0, entries: [] }; }
function emptyPages(): Pages { return { packets: emptyPage(), hosts: emptyPage(), flows: emptyPage() }; }
function message(error: unknown): string { return error instanceof Error ? error.message : String(error); }
function bytesAsHex(bytes: number[], startOffset = 0): string {
  const rows: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = chunk.map((value) => value.toString(16).padStart(2, "0")).join(" ");
    const ascii = chunk.map((value) => value >= 32 && value <= 126 ? String.fromCharCode(value) : ".").join("");
    rows.push(`${(startOffset + i).toString(16).padStart(4, "0")}  ${hex.padEnd(47)}  ${ascii}`);
  }
  return rows.join("\n");
}

/** Native jobs continue in Rust across route navigation; cache only a session reference, never raw evidence. */
export function LiveCaptureView({ presentation = "full", onCaptureStarted, onReturnToStart, onOpenSavedArtifact, onOpenCaptureFile }: {
  presentation?: "setup" | "full";
  onCaptureStarted?: () => void;
  onReturnToStart?: () => void;
  onOpenSavedArtifact?: (artifactId: string) => void;
  onOpenCaptureFile?: () => void;
}) {
  const desktop = isDesktop();
  const [nativePlatform, setNativePlatform] = useState<"windows" | "linux" | "macos" | "unsupported" | null>(null);
  const [nativeCaptureStatus, setNativeCaptureStatus] = useState<string | null>(null);
  const windowsHost = nativePlatform === "windows";
  useEffect(() => {
    if (!desktop) return;
    let live = true;
    void networkRuntimeCapabilitiesV1()
      .then((caps) => {
        if (!live) return;
        setNativePlatform(caps.platform);
        setNativeCaptureStatus(caps.capture_detail);
      })
      .catch((error) => { if (live) setNativeCaptureStatus("Native capability inventory unavailable: " + message(error)); });
    return () => { live = false; };
  }, [desktop]);
  const { caseId, caseSession } = useWorkbenchCase();
  const revision = caseSession.phase === "ready" && caseSession.caseId === caseId ? caseSession.revision : null;
  const identity = caseId + ":" + String(revision);
  const currentIdentity = useRef(identity);
  currentIdentity.current = identity;
  const token = useRef(0);
  const pollRequest = useRef(0);
  const frameRequest = useRef(0);
  const pageRequest = useRef(0);
  const [reference, setReference] = useWorkspaceDraft<SessionRef | null>(caseId, "network", "capture-session-ref", null);
  const nativeReference = useSyncExternalStore(subscribeNativeSessions, () => currentNativeSession(identity), () => null);
  const sessionId = revision === null ? null : nativeReference ?? activeCaptureId(reference, revision);
  const [devices, setDevices] = useState<CaptureInterfaceV1[]>([]);
  const [device, setDevice] = useWorkspaceDraft(caseId, "network", "capture-device", "");
  const [maxPackets, setMaxPackets] = useWorkspaceDraft(caseId, "network", "capture-frames", "4000");
  const [memoryMiB, setMemoryMiB] = useWorkspaceDraft(caseId, "network", "capture-memory", "8");
  const [seconds, setSeconds] = useWorkspaceDraft(caseId, "network", "capture-time", "60");
  const [tab, setTab] = useWorkspaceDraft<Tab>(caseId, "network", "capture-tab", "packets");
  const [status, setStatus] = useState<CaptureStatusV1 | null>(null);
  const [pages, setPages] = useState<Pages>(emptyPages);
  const [frame, setFrame] = useState<CaptureFramePageV1 | null>(null);
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const [detailsWidth, setDetailsWidth] = useState<number | null>(null);
  const [working, setWorking] = useState(false);
  const [loadingPages, setLoadingPages] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<CaptureSaveReceiptV1 | null>(null);
  const [decoded, setDecoded] = useState<PcapPacketWire | null>(null);
  const [stream, setStream] = useState<StreamTranscriptWire | null>(null);
  const [streamBusy, setStreamBusy] = useState(false);
  const [showLimits, setShowLimits] = useState(false);
  const [activity, setActivity] = useState<CaptureActivityPoint[]>([]);

  const valid = useCallback((key: string, version: number) =>
    currentIdentity.current === key && token.current === version, []);
  const eligible = devices.filter(captureInterfaceEligible);
  const running = status?.phase === "running" || status?.phase === "stopping";
  const readable = status?.results_available === true && matchesCaptureIdentity(status, sessionId, caseId);
  const canStart = desktop && revision !== null && !running && !working && eligible.some((entry) => entry.name === device);

  useEffect(() => {
    token.current++;
    pollRequest.current++;
    frameRequest.current++;
    pageRequest.current++;
    setStatus(null); setPages(emptyPages()); setSelectedIndex(null); setFrame(null);
    setError(null); setDevices([]); setWorking(false); setActivity([]);
    setSaving(false); setSaved(null); setDecoded(null); setStream(null);
  }, [identity]);

  const discover = useCallback(async () => {
    if (!desktop) return;
    const key = identity, version = token.current;
    try {
      const list = await captureInterfacesV1();
      if (!valid(key, version)) return;
      setDevices(list);
      if (!list.some((entry) => entry.name === device && captureInterfaceEligible(entry))) {
        setDevice(list.find((entry) => captureInterfaceEligible(entry))?.name ?? "");
      }
    } catch (cause) {
      if (valid(key, version)) setError("Interface discovery: " + message(cause));
    }
  }, [desktop, identity, valid, device, setDevice]);

  useEffect(() => {
    void discover();
    // New case revision only, not each dropdown change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [desktop, identity]);

  const poll = useCallback(async (id: number, key: string, version: number) => {
    const order = ++pollRequest.current;
    try {
      const next = await captureStatusV1(id);
      if (!valid(key, version) || order !== pollRequest.current) return;
      if (!matchesCaptureIdentity(next, id, caseId)) throw new Error("backend capture identity changed");
      setStatus(next);
      setActivity((history) => [...history, { at: Date.now(), packets: next.progress.packets }].slice(-36));
      if (next.phase === "failed") setError((next.error?.code ?? "failed") + ": " + (next.error?.message ?? "capture failed"));
    } catch (cause) {
      if (!valid(key, version) || order !== pollRequest.current) return;
      dropNativeSession(key);
      setReference(null);
      setStatus(null); setPages(emptyPages()); setFrame(null);
      setError("Capture unavailable for the selected case: " + message(cause));
    }
  }, [valid, caseId, setReference]);

  useEffect(() => {
    if (!desktop || sessionId === null || status?.phase === "completed" || status?.phase === "failed") return;
    const key = identity, version = token.current;
    void poll(sessionId, key, version);
    const interval = setInterval(() => { void poll(sessionId, key, version); }, 900);
    // Do not stop the backend when the page unmounts or another tool opens.
    return () => clearInterval(interval);
  }, [desktop, sessionId, identity, poll, status?.phase]);

  const loadPages = useCallback(async (id: number, key: string, version: number, offsets: Record<DataTab, number>) => {
    const order = ++pageRequest.current;
    setLoadingPages(true);
    try {
      const [packets, hosts, flows] = await Promise.all([
        captureProvenanceV1(id, offsets.packets, SIZE),
        captureHostsV1(id, offsets.hosts, SIZE),
        captureFlowsV1(id, offsets.flows, SIZE),
      ]);
      if (valid(key, version) && order === pageRequest.current) setPages({ packets, hosts, flows });
    } catch (cause) {
      if (valid(key, version) && order === pageRequest.current) setError("Inventory read: " + message(cause));
    } finally {
      if (valid(key, version) && order === pageRequest.current) setLoadingPages(false);
    }
  }, [valid]);

  useEffect(() => {
    if (!readable || sessionId === null) return;
    void loadPages(sessionId, identity, token.current, { packets: 0, hosts: 0, flows: 0 });
  }, [readable, sessionId, identity, loadPages]);

  async function start(selectedDevice = device) {
    if (!desktop || running || working || !eligible.some((entry) => entry.name === selectedDevice)) return;
    if (revision === null) { setError("Select an authorized saved case to start live capture."); return; }
    const limits = captureLimits(maxPackets, memoryMiB, seconds);
    if (!limits) {
      setError("Use whole-number limits: 1–20000 packets, 1–16 MiB and 1–600 seconds."); return;
    }
    const key = identity, version = ++token.current;
    setWorking(true); setStatus(null); setPages(emptyPages()); setFrame(null); setError(null); setActivity([]); setSaved(null); setDecoded(null); setStream(null);
    try {
      const next = await captureStartV1(selectedDevice, limits);
      if (next.case_id !== caseId || !Number.isSafeInteger(next.session_id) || next.session_id <= 0) throw new Error("invalid backend capture identity");
      // The native dialog may resolve after this route unmounts. Keep only the
      // backend-owned identity so a later mount can resume status and Stop.
      rememberNativeSession(key, next.session_id);
      if (!valid(key, version)) return;
      setReference({ id: next.session_id, revision });
      setStatus(next);
      onCaptureStarted?.();
    } catch (cause) {
      if (valid(key, version)) setError("Capture start: " + message(cause));
    } finally {
      if (valid(key, version)) setWorking(false);
    }
  }

  async function stop() {
    if (sessionId === null || !running) return;
    pollRequest.current++;
    const key = identity, version = token.current;
    setWorking(true);
    try {
      const next = await captureStopV1(sessionId);
      if (valid(key, version)) setStatus(next);
    } catch (cause) {
      if (valid(key, version)) setError("Capture stop: " + message(cause));
    } finally {
      if (valid(key, version)) setWorking(false);
    }
  }

  async function save() {
    if (!readable || sessionId === null || saving) return;
    const key = identity;
    const version = token.current;
    setSaving(true);
    setError(null);
    try {
      // Backend independently confirms operator approval and case generation
      // before committing the original bytes. No raw PCAP crosses frontend IPC.
      const receipt = await captureSaveV1(sessionId);
      if (!valid(key, version)) return;
      if (receipt.case_id !== caseId || receipt.session_id !== sessionId
        || !/^[0-9a-f]{64}$/.test(receipt.sha256)) {
        throw new Error("backend returned a mismatched artifact receipt");
      }
      setSaved(receipt);
    } catch (cause) {
      if (valid(key, version)) {
        const reason = message(cause);
        if (!reason.includes("cancelled by operator")) setError("Save capture: " + reason);
      }
    } finally {
      if (valid(key, version)) setSaving(false);
    }
  }

  async function inspect(index: number, offset = 0) {
    if (!readable || sessionId === null) return;
    const key = identity, version = token.current;
    const order = ++frameRequest.current;
    setSelectedIndex(index); setFrame(null);
    if (offset === 0) { setDecoded(null); setStream(null); }
    try {
      const [raw, packet] = await Promise.all([
        captureFramePageV1(sessionId, index, offset, 4096),
        offset === 0 ? capturePacketDetailsV1(sessionId, index) : Promise.resolve(null),
      ]);
      if (!valid(key, version) || order !== frameRequest.current || raw.index !== index) return;
      setFrame(raw);
      if (packet) setDecoded(packet);
    } catch (cause) {
      if (valid(key, version) && order === frameRequest.current) setError("Original frame inspection: " + message(cause));
    }
  }

  async function followSelectedStream() {
    if (!readable || sessionId === null || !decoded?.stream_id || streamBusy) return;
    const key = identity, version = token.current, order = frameRequest.current;
    setStreamBusy(true);
    try {
      const transcript = await captureFollowStreamV1(sessionId, decoded.stream_id);
      if (valid(key, version) && order === frameRequest.current) setStream(transcript);
    } catch (cause) {
      if (valid(key, version) && order === frameRequest.current) setError("Stream follow: " + message(cause));
    } finally {
      if (valid(key, version)) setStreamBusy(false);
    }
  }

  function movePage(delta: number) {
    const current = pages[tab === "statistics" ? "packets" : tab];
    const offset = boundedPageOffset(current.offset, current.total, delta, SIZE);
    if (!readable || sessionId === null || loadingPages || tab === "statistics" || offset === null) return;
    void loadPages(sessionId, identity, token.current, {
      packets: tab === "packets" ? offset : pages.packets.offset,
      hosts: tab === "hosts" ? offset : pages.hosts.offset,
      flows: tab === "flows" ? offset : pages.flows.offset,
    });
  }

  const page = pages[tab === "statistics" ? "packets" : tab];
  if (presentation === "setup") {
    return (
      <section aria-label="Capture interfaces" className="w-full px-5 pb-5 sm:px-7">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-baseline gap-3">
            <h2 className="text-sm font-semibold">Capture</h2>
            {desktop && (
              <span className="text-xs text-fg-muted">
                {devices.length ? `${eligible.length} available · ${devices.length} found` : "Interfaces"}
              </span>
            )}
          </div>
          {desktop && (
            <Button size="xs" variant="ghost" onClick={() => void discover()}
              title="Refresh network interfaces" aria-label="Refresh network interfaces">
              <RefreshCw size={14} /> Refresh
            </Button>
          )}
        </div>
        {!desktop ? (
          <div className="flex flex-col items-start gap-2 py-2">
            <Router label="Network interfaces unavailable" theme="auto" className="w-80 max-w-full opacity-50" />
            <p className="text-xs text-fg-muted">Live capture requires the desktop application.</p>
          </div>
        ) : (
          <div className="min-w-0">
            {devices.length === 0 ? (
              <p className="px-4 py-4 text-sm text-fg-muted">
                No native network adapters found. Use Refresh to retry.
              </p>
            ) : (
              <div aria-label="Native capture interfaces" className="max-h-52 overflow-y-auto">
                {devices.map((entry) => {
                  const supported = entry.up && entry.ethernet && !entry.loopback && entry.capture_supported !== false;
                  const selected = device === entry.name;
                  return (
                    <Button key={entry.index + ":" + entry.name} type="button"
                      aria-pressed={selected} disabled={!supported || running || working}
                      variant="ghost" size="sm"
                      onClick={() => { setDevice(entry.name); void start(entry.name); }}
                      className={`flex h-auto min-h-10 w-full justify-start gap-3 rounded-none border-b border-line px-4 py-2.5 text-left font-normal last:border-b-0 hover:bg-accent ${selected ? "bg-selected" : ""}`}>
                      <span aria-hidden="true" className={`size-2.5 shrink-0 rounded-full border ${selected ? "border-fg bg-fg" : "border-fg-muted"}`} />
                      <MonitorDot size={16} className="shrink-0 text-fg-muted" />
                      <span className="min-w-0 flex-1 truncate text-xs text-fg" title={entry.display_name || (windowsHost ? "Windows adapter #" + entry.index : entry.name)}>
                          {entry.display_name || (windowsHost ? "Windows adapter #" + entry.index : entry.name)}
                        </span>
                      <span className="shrink-0 text-xs text-fg-muted">
                        {entry.loopback ? "Loopback" : entry.ethernet ? "Ethernet" : "Other"}
                      </span>
                      <span title={entry.capture_unavailable_reason ?? undefined} className={`shrink-0 text-xs ${supported ? "text-fg-dim" : "text-fg-muted"}`}>
                        {entry.up ? supported ? "Ready" : entry.capture_supported === false ? "Driver unavailable" : "Unsupported" : "Down"}
                      </span>
                    </Button>
                  );
                })}
              </div>
            )}
            {windowsHost && eligible.length === 0 && (
              <div role="status" className="mt-3 space-y-2 rounded-md border border-line p-3 text-xs text-fg-dim">
                <p className="font-medium text-fg">Windows live packet capture is not operational</p>
                <p>Windows adapters are listed by their OS display names. Live Ethernet frame capture requires a compatible native capture driver; adapter discovery alone cannot record packets.</p>
                {nativeCaptureStatus && <p className="font-mono text-[11px]">{nativeCaptureStatus}</p>}
                <p>You can still analyze PCAP/PCAPNG files with the native Rust packet analyzer.</p>
                {onOpenCaptureFile && <Button size="sm" variant="outline" onClick={onOpenCaptureFile}><FolderOpen size={14} /> Open capture file</Button>}
              </div>
            )}
            {eligible.length === 0 && devices.some((entry) => entry.capture_unavailable_reason) && (
              <p role="status" className="mt-2 px-4 text-xs text-fg-muted">
                {devices.find((entry) => entry.capture_unavailable_reason)?.capture_unavailable_reason}
              </p>
            )}
          </div>
        )}
        {revision === null && eligible.length > 0 && <AuthorizedCaseAction activity="Live packet capture" />}
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {running && sessionId !== null && (
            <Button variant="destructive-outline" size="sm" disabled={working || status?.phase === "stopping"}
              onClick={() => void stop()}><Square size={13} /> Stop</Button>
          )}
          {sessionId !== null && (
            <Button variant="outline" size="sm" onClick={() => onCaptureStarted?.()}>
              View Capture
            </Button>
          )}
          {desktop && (
            <Button variant="ghost" size="sm" aria-expanded={showLimits}
              aria-controls="capture-advanced-limits" onClick={() => setShowLimits((value) => !value)}>
              <Settings2 size={14} /> Options
            </Button>
          )}
          {desktop && (
            <Button variant="ghost" size="icon" aria-label="Capture permissions and limitations"
              title="Native Linux capture requires case consent and CAP_NET_RAW. Windows native adapter discovery is available but full-fidelity Ethernet frame capture is pending an independent driver/host test.">
              <Info size={14} aria-hidden="true" />
            </Button>
          )}
          {desktop && revision === null && (
            <span className="text-xs text-fg-muted">Saved case required</span>
          )}
          {status && (
            <div className="ml-auto flex items-center gap-2"><CaptureActivity samples={activity}/><span className="text-xs text-fg-muted">
              {status.phase} · {status.progress.packets} frames
            </span></div>
          )}
        </div>
        {showLimits && desktop && (
          <div id="capture-advanced-limits" className="mt-3 flex flex-wrap gap-3 rounded-md border border-line bg-panel p-3">
            <label className="flex flex-col gap-1 text-xs text-fg-muted">Packets
              <TextInput value={maxPackets} onChange={setMaxPackets} ariaLabel="Maximum packets" className="w-28" />
            </label>
            <label className="flex flex-col gap-1 text-xs text-fg-muted">Memory (MiB)
              <TextInput value={memoryMiB} onChange={setMemoryMiB} ariaLabel="Memory limit in MiB" className="w-28" />
            </label>
            <label className="flex flex-col gap-1 text-xs text-fg-muted">Duration (s)
              <TextInput value={seconds} onChange={setSeconds} ariaLabel="Maximum capture seconds" className="w-28" />
            </label>
          </div>
        )}
        {(error || caseSession.error) && (
          <p role="alert" className="mt-3 text-xs text-err">{error || caseSession.error}</p>
        )}
      </section>
    );
  }
  const selectedPacket = pages.packets.entries.find((packet) => packet.packet_index === selectedIndex);
  return (
    <div className="flex h-full min-h-0 flex-col" aria-label="Native packet analyzer">
      <div className="cd-workspace-toolbar shrink-0 items-center gap-2 px-2">
        {onReturnToStart && (
          <Button variant="ghost" size="sm" onClick={onReturnToStart}>Capture selection</Button>
        )}
        <span className="text-[10px] uppercase text-fg-muted">Interface</span>
        <Select value={device} onChange={setDevice} ariaLabel="Native capture interface" className="w-44"
          options={eligible.length ? eligible.map((entry) => ({ value: entry.name, label: entry.name + " · " + entry.index })) :
            [{ value: "-", label: "No eligible Ethernet interface" }]} />
        <ToolButton onClick={() => void discover()} disabled={!desktop} title="Refresh native interface list">
          <RefreshCw size={12} /> Refresh
        </ToolButton>
        {running ? (
          <ToolButton tone="danger" onClick={() => void stop()} disabled={working || status?.phase === "stopping"}>
            <Square size={12} /> {status?.phase === "stopping" ? "Stopping…" : "Stop"}
          </ToolButton>
        ) : (
          <ToolButton tone="primary" onClick={() => void start()} disabled={!canStart}
            title="Requires a saved case, explicit native confirmation and OS capture permissions; Windows also requires the independently signed CyberDeck capture driver">
            <Play size={12} /> {working ? "Confirming…" : "Start Capture"}
          </ToolButton>
        )}
        <Chip tone={running ? "orange" : status?.phase === "failed" ? "err" : readable ? "ok" : "muted"}>
          {status?.phase ?? "idle"}
        </Chip>
        <span className="ml-auto flex items-center gap-2 truncate text-[10px] text-fg-muted">
          <CaptureActivity samples={activity}/>
          {status ? status.progress.packets + " frames · " + status.progress.stored_pcap_bytes + " PCAP bytes" : "Native Ethernet capture"}
        </span>
      </div>
      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-line px-3 py-1.5 text-[11px] text-fg-muted">
        <label>Packets <TextInput value={maxPackets} onChange={setMaxPackets} ariaLabel="Maximum packets" className="ml-1 inline-flex w-20" /></label>
        <label>Memory MiB <TextInput value={memoryMiB} onChange={setMemoryMiB} ariaLabel="Memory budget MiB" className="ml-1 inline-flex w-16" /></label>
        <label>Duration s <TextInput value={seconds} onChange={setSeconds} ariaLabel="Capture duration in seconds" className="ml-1 inline-flex w-16" /></label>
        <span>{revision === null ? "Saved case required for live capture." : "Case " + caseId + " · rev " + revision}</span>
        <ToolButton disabled={!readable || saving} onClick={() => void save()}
          title={readable ? "Save the byte-exact original PCAP as immutable case evidence, after native confirmation" : "Complete a capture with original frames first"}>
          {saving ? "Saving…" : saved ? "Saved to Case" : "Save Capture to Case"}
        </ToolButton>
        {saved && onOpenSavedArtifact && (
          <ToolButton onClick={() => onOpenSavedArtifact(saved.artifact_id)} title="Reopen SHA-256-verified case PCAP in the full packet analyzer">
            Open Verified Capture
          </ToolButton>
        )}
        {saved && <span className="font-mono text-[10px] text-fg-muted" title={saved.artifact_id}>
          SHA-256 {saved.sha256.slice(0, 16)}… · {saved.frame_count} frames verified
        </span>}
      </div>
      {(error || caseSession.error) && (
        <p role="alert" className="border-b border-err/50 bg-err/10 px-3 py-1 text-xs text-err">{error || caseSession.error}</p>
      )}
      {status && (
        <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-line px-3 py-1 text-[10px] text-fg-muted">
          <span>Session #{status.session_id} · {status.interface}</span>
          <span>Packets {status.progress.packets}</span>
          <span>Oversized discarded {status.progress.oversized_frames_discarded}</span>
          {status.stop_reason && <span>Stop: {status.stop_reason}</span>}
          {!readable && running && <span>Frame inspection available once capture completes</span>}
        </div>
      )}
      <PacketPaneSplit
        list={<div className="flex h-full min-h-0 flex-col">
        <div className="min-h-0 flex-1 overflow-auto bg-panel">
          {tab === "packets" ? (
            <PacketTable
              rows={pages.packets.entries.map(nativeCapturePacketRow)}
              selectedIndex={selectedIndex}
              onSelect={(index) => void inspect(index)}
              empty={running
                ? "Capturing frames… live progress is shown above; packet pages are published when the Rust capture finishes."
                : readable ? "No captured frames in this page" : "Select an interface and start capture, or open a PCAP from Capture selection."}
            />
          ) : tab === "hosts" ? (
            <table className="data-table w-full" aria-label="Captured hosts">
              <thead><tr><th>Host</th><th>First frame</th><th>Last frame</th><th>Sent</th><th>Received</th><th>Bytes</th></tr></thead>
              <tbody>{pages.hosts.entries.map((entry) => (
                <tr key={entry.address} className="cursor-pointer" onClick={() => { setTab("packets"); void inspect(entry.first_packet_index); }}>
                  <td>{entry.address}</td><td>{entry.first_packet_index + 1}</td><td>{entry.last_packet_index + 1}</td>
                  <td>{entry.packets_sent}</td><td>{entry.packets_received}</td>
                  <td>{entry.captured_bytes_sent + entry.captured_bytes_received}</td>
                </tr>
              ))}</tbody>
            </table>
          ) : tab === "flows" ? (
            <table className="data-table w-full" aria-label="Captured flows">
              <thead><tr><th>Flow</th><th>First frame</th><th>Last frame</th><th>Packets</th><th>Bytes</th></tr></thead>
              <tbody>{pages.flows.entries.map((entry) => (
                <tr key={entry.stream_id} className="cursor-pointer" onClick={() => { setTab("packets"); void inspect(entry.first_packet_index); }}>
                  <td className="max-w-80 truncate" title={entry.stream_id}>{entry.stream_id}</td>
                  <td>{entry.first_packet_index + 1}</td><td>{entry.last_packet_index + 1}</td>
                  <td>{entry.packet_count}</td><td>{entry.captured_bytes}</td>
                </tr>
              ))}</tbody>
            </table>
          ) : (
            <div className="grid gap-3 p-4 text-xs sm:grid-cols-2 lg:grid-cols-4" aria-label="Capture statistics">
              {[
                ["Captured packets", status?.progress.packets ?? 0],
                ["Stored PCAP bytes", status?.progress.stored_pcap_bytes ?? 0],
                ["Oversized discarded", status?.progress.oversized_frames_discarded ?? 0],
                ["Captured hosts / flows", readable ? pages.hosts.total + " / " + pages.flows.total : "Available on completion"],
              ].map(([label, value]) => (
                <div key={label} className="rounded border border-line bg-panel p-3">
                  <div className="text-fg-muted">{label}</div>
                  <div className="mt-1 font-mono text-base text-fg">{value}</div>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="flex shrink-0 items-center justify-between border-b border-line px-2 py-1 text-[11px] text-fg-muted">
          <span>{readable && tab !== "statistics" && page.total
            ? page.offset + 1 + "–" + (page.offset + page.entries.length) + " of " + page.total
            : running ? "Capture in progress" : readable ? "No rows" : "No completed native capture"}
          </span>
          <div className="flex gap-1">
            <ToolButton disabled={!readable || tab === "statistics" || loadingPages || page.offset === 0} onClick={() => movePage(-1)}>Previous</ToolButton>
            <ToolButton disabled={!readable || tab === "statistics" || loadingPages || page.offset + SIZE >= page.total} onClick={() => movePage(1)}>Next</ToolButton>
          </div>
        </div>
</div>}
        detailTitle={`Packet details: ${selectedIndex === null ? "no selection" : "frame " + (selectedIndex + 1)}`}
        details={            <div className="min-h-0 flex-1 overflow-auto p-2 text-xs">
              {selectedPacket ? (
                <dl className="space-y-1 font-mono">
                  <div><dt className="inline text-fg-muted">Frame: </dt><dd className="inline">{selectedPacket.packet_index + 1}</dd></div>
                  <div><dt className="inline text-fg-muted">Source: </dt><dd className="inline">{selectedPacket.source ?? "Unknown"}</dd></div>
                  <div><dt className="inline text-fg-muted">Destination: </dt><dd className="inline">{selectedPacket.destination ?? "Unknown"}</dd></div>
                  <div><dt className="inline text-fg-muted">Captured / wire length: </dt><dd className="inline">{selectedPacket.captured_length} / {selectedPacket.wire_length} bytes</dd></div>
                  <div><dt className="inline text-fg-muted">PCAP frame offset: </dt><dd className="inline">{selectedPacket.pcap_frame_offset}</dd></div>
                  {selectedPacket.stream_id && <div><dt className="inline text-fg-muted">Stream: </dt><dd className="inline break-all">{selectedPacket.stream_id}</dd></div>}
                  {decoded && (
                    <div className="mt-2 space-y-1 border-t border-line pt-2">
                      <div className="text-fg">{decoded.protocol} · {decoded.info}</div>
                      <div>Relative time: {(decoded.time_ms / 1000).toFixed(6)} s</div>
                      {decoded.layers.map((layer, index) => (
                        <div key={index} className="break-words"><span className="text-fg-muted">{layer.label}: </span>{layer.value}</div>
                      ))}
                      {decoded.stream_id && (
                        <ToolButton onClick={() => void followSelectedStream()} disabled={streamBusy}>
                          {streamBusy ? "Following…" : "Follow native stream"}
                        </ToolButton>
                      )}
                    </div>
                  )}
                  {stream && (
                    <div className="mt-2 border-t border-line pt-2">
                      <div className="mb-1 flex items-center justify-between">
                        <span>{stream.protocol} stream · {stream.chunks.length} chunks · {stream.gaps} gaps</span>
                        <ToolButton onClick={() => setStream(null)}>Hide stream</ToolButton>
                      </div>
                      <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all text-[10px]">{stream.chunks.map((chunk) => "[" + chunk.dir + " / " + chunk.kind + "] " + chunk.text).join("\n")}</pre>
                      {stream.truncated && <p className="text-warn">Stream reconstruction was truncated at native safety limits.</p>}
                    </div>
                  )}
                  {!decoded && <p className="pt-2 text-[11px] text-fg-muted">Decoded protocol layers are retrieved from the original capture using the shared native Rust parser.</p>}
                </dl>
              ) : (
                <EmptyState title="Select a captured packet" detail={running
                  ? "The Rust capture worker is running; packet inspection becomes available after completion."
                  : "Inspect the packet's native provenance after a completed capture."} />
              )}
            </div>
}
        bytesTitle="Packet bytes (offset · hex · ASCII)"
        bytesActions={<ToolButton disabled={!frame || frame.offset + frame.bytes.length >= frame.frame_length}
                onClick={() => { if (frame) void inspect(frame.index, frame.offset + frame.bytes.length); }}>
                Next 4 KiB
              </ToolButton>}
        bytes={            <div className="min-h-0 flex-1 overflow-auto p-2">
              {frame ? (
                <>
                  <p className="mb-2 text-[10px] text-fg-muted">
                    Original captured frame {frame.index + 1} · bytes {frame.offset}–{frame.offset + frame.bytes.length} of {frame.frame_length}
                  </p>
                  <pre className="whitespace-pre font-mono text-[11px] leading-relaxed text-fg-dim">{bytesAsHex(frame.bytes, frame.offset)}</pre>
                </>
              ) : (
                <EmptyState title="No frame bytes selected" detail="Select a completed native capture frame to inspect byte-exact original content." />
              )}
            </div>
}
      />
      <WorkspaceTabs items={["packets", "hosts", "flows", "statistics"] as const}
        active={tab} onChange={setTab} placement="bottom" ariaLabel="Native packet investigation views" />
    </div>
  );
}

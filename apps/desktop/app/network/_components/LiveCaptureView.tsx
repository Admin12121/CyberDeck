"use client";

import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";
import { Play, RefreshCw, Square } from "lucide-react";
import { Chip, EmptyState, Pane, Select, TextInput, ToolButton, WorkspaceTabs } from "@ds/panes";
import {
  isDesktop, captureInterfacesV1, captureStartV1, captureStatusV1, captureStopV1,
  captureProvenanceV1, captureHostsV1, captureFlowsV1, captureFramePageV1,
  type CaptureInterfaceV1, type CaptureStatusV1, type CapturePageV1,
  type CaptureFrameProvenanceV1, type CaptureHostV1, type CaptureFlowV1,
  type CaptureFramePageV1,
} from "@lib/ipc";
import { useWorkbenchCase } from "@state/workbench";
import { useWorkspaceDraft } from "@state/workspace-sessions";
import { activeCaptureId, boundedPageOffset, captureLimits, matchesCaptureIdentity } from "./capture-view-policy";
import { currentNativeSession, dropNativeSession, rememberNativeSession, subscribeNativeSessions } from "./capture-session-registry";

type Tab = "packets" | "hosts" | "flows";
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
  return bytes.map((byte, index) => (index % 16 === 0 ? (index ? "\n" : "") + (startOffset + index).toString(16).padStart(4, "0") + "  " : " ") + byte.toString(16).padStart(2, "0")).join("");
}

/** Native jobs continue in Rust across route navigation; cache only a session reference, never raw evidence. */
export function LiveCaptureView() {
  const desktop = isDesktop();
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
  const [working, setWorking] = useState(false);
  const [loadingPages, setLoadingPages] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const valid = useCallback((key: string, version: number) =>
    currentIdentity.current === key && token.current === version, []);
  const eligible = devices.filter((entry) => entry.up && entry.ethernet && !entry.loopback);
  const running = status?.phase === "running" || status?.phase === "stopping";
  const readable = status?.results_available === true && matchesCaptureIdentity(status, sessionId, caseId);
  const canStart = desktop && revision !== null && !running && !working && eligible.some((entry) => entry.name === device);

  useEffect(() => {
    token.current++;
    pollRequest.current++;
    frameRequest.current++;
    pageRequest.current++;
    setStatus(null); setPages(emptyPages()); setSelectedIndex(null); setFrame(null);
    setError(null); setDevices([]); setWorking(false);
  }, [identity]);

  const discover = useCallback(async () => {
    if (!desktop) return;
    const key = identity, version = token.current;
    try {
      const list = await captureInterfacesV1();
      if (!valid(key, version)) return;
      setDevices(list);
      if (!list.some((entry) => entry.name === device && entry.up && entry.ethernet && !entry.loopback)) {
        setDevice(list.find((entry) => entry.up && entry.ethernet && !entry.loopback)?.name ?? "");
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

  const loadPages = useCallback(async (id: number, key: string, version: number, offsets: Record<Tab, number>) => {
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

  async function start() {
    if (!canStart || revision === null) return;
    const limits = captureLimits(maxPackets, memoryMiB, seconds);
    if (!limits) {
      setError("Use whole-number limits: 1–20000 packets, 1–16 MiB and 1–600 seconds."); return;
    }
    const key = identity, version = ++token.current;
    setWorking(true); setStatus(null); setPages(emptyPages()); setFrame(null); setError(null);
    try {
      const next = await captureStartV1(device, limits);
      if (next.case_id !== caseId || !Number.isSafeInteger(next.session_id) || next.session_id <= 0) throw new Error("invalid backend capture identity");
      // The native dialog may resolve after this route unmounts. Keep only the
      // backend-owned identity so a later mount can resume status and Stop.
      rememberNativeSession(key, next.session_id);
      if (!valid(key, version)) return;
      setReference({ id: next.session_id, revision });
      setStatus(next);
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

  async function inspect(index: number, offset = 0) {
    if (!readable || sessionId === null) return;
    const key = identity, version = token.current;
    const order = ++frameRequest.current;
    setSelectedIndex(index); setFrame(null);
    try {
      const next = await captureFramePageV1(sessionId, index, offset, 4096);
      if (valid(key, version) && order === frameRequest.current && next.index === index) setFrame(next);
    } catch (cause) {
      if (valid(key, version) && order === frameRequest.current) setError("Original frame read: " + message(cause));
    }
  }

  function movePage(delta: number) {
    const current = pages[tab];
    const offset = boundedPageOffset(current.offset, current.total, delta, SIZE);
    if (!readable || sessionId === null || loadingPages || offset === null) return;
    void loadPages(sessionId, identity, token.current, {
      packets: tab === "packets" ? offset : pages.packets.offset,
      hosts: tab === "hosts" ? offset : pages.hosts.offset,
      flows: tab === "flows" ? offset : pages.flows.offset,
    });
  }

  const page = pages[tab];
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="cd-workspace-toolbar shrink-0 items-center gap-2 px-2">
        <span className="text-[10px] uppercase text-fg-muted">Interface</span>
        <Select value={device} onChange={setDevice} ariaLabel="Native capture interface" className="w-44"
          options={eligible.length ? eligible.map((entry) => ({ value: entry.name, label: entry.name + " · " + entry.index })) :
            [{ value: "-", label: "No eligible Ethernet interface" }]} />
        <ToolButton onClick={() => void discover()} disabled={!desktop} title="Refresh native interface list"><RefreshCw size={12} /> Refresh</ToolButton>
        {running ? (
          <ToolButton tone="danger" onClick={() => void stop()} disabled={working || status?.phase === "stopping"}>
            <Square size={12} /> {status?.phase === "stopping" ? "Stopping…" : "Stop"}
          </ToolButton>
        ) : (
          <ToolButton tone="primary" onClick={() => void start()} disabled={!canStart}
            title="Requires a selected investigation case, native confirmation and Linux CAP_NET_RAW">
            <Play size={12} /> {working ? "Confirming…" : "Capture"}
          </ToolButton>
        )}
        <Chip tone={running ? "orange" : status?.phase === "failed" ? "err" : readable ? "ok" : "muted"}>{status?.phase ?? "idle"}</Chip>
        <span className="ml-auto text-[10px] text-fg-muted">{status ? String(status.progress.packets) + " frames · " + String(status.progress.stored_pcap_bytes) + " PCAP bytes" : "Native Linux Ethernet"}</span>
      </div>
      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-line px-3 py-2 text-[11px] text-fg-muted">
        <label>Packets <TextInput value={maxPackets} onChange={setMaxPackets} ariaLabel="Maximum packets" className="ml-1 inline-flex w-20" /></label>
        <label>Memory MiB <TextInput value={memoryMiB} onChange={setMemoryMiB} ariaLabel="Memory budget MiB" className="ml-1 inline-flex w-16" /></label>
        <label>Duration s <TextInput value={seconds} onChange={setSeconds} ariaLabel="Capture duration in seconds" className="ml-1 inline-flex w-16" /></label>
        <span>{revision === null ? "Select a saved investigation case (temporary workspace cannot capture)." : "Case " + caseId + " · revision " + revision}</span>
        <ToolButton disabled title="Immutable Save-to-Case requires the approved storage transaction and digest readback">Save to Case unavailable</ToolButton>
      </div>
      {(error || caseSession.error) ? <div role="alert" className="border-b border-err/50 bg-err/10 px-3 py-1 text-xs text-err">{error || caseSession.error}</div> : null}
      <WorkspaceTabs items={["packets", "hosts", "flows"] as const} active={tab} onChange={setTab} ariaLabel="Captured packets and passive inventory" />
      {status && <div className="flex shrink-0 flex-wrap gap-3 border-b border-line px-3 py-1 text-[10px] text-fg-muted">
        <span>Session #{status.session_id} · {status.interface}</span>
        <span>Packets {status.progress.packets}</span>
        <span>Oversized discarded {status.progress.oversized_frames_discarded}</span>
        <span>{status.stop_reason ? "Stop: " + status.stop_reason : "Capture active or pending"}</span>
      </div>}
      <div className="min-h-0 flex-1 flex flex-col">
        {readable ? (
          <>
            <div className="min-h-0 flex-1 overflow-auto">
              {tab === "packets" ? <table className="data-table">
                <thead><tr><th>Frame</th><th>PCAP offset</th><th>Source</th><th>Destination</th><th>Length</th><th>Flow</th></tr></thead>
                <tbody>{pages.packets.entries.map((entry) => (
                  <tr key={entry.packet_index} className="cursor-pointer" onClick={() => void inspect(entry.packet_index)}>
                    <td>{entry.packet_index}</td><td>{entry.pcap_frame_offset}</td>
                    <td>{entry.source ?? "—"}</td><td>{entry.destination ?? "—"}</td>
                    <td>{entry.captured_length}</td><td className="max-w-64 truncate" title={entry.stream_id ?? ""}>{entry.stream_id ?? "—"}</td>
                  </tr>
                ))}</tbody>
              </table> : tab === "hosts" ? <table className="data-table">
                <thead><tr><th>Host</th><th>First frame</th><th>Last frame</th><th>Sent</th><th>Received</th><th>Bytes</th></tr></thead>
                <tbody>{pages.hosts.entries.map((entry) => (
                  <tr key={entry.address} className="cursor-pointer" onClick={() => { setTab("packets"); void inspect(entry.first_packet_index); }}>
                    <td>{entry.address}</td><td>{entry.first_packet_index}</td><td>{entry.last_packet_index}</td>
                    <td>{entry.packets_sent}</td><td>{entry.packets_received}</td>
                    <td>{entry.captured_bytes_sent + entry.captured_bytes_received}</td>
                  </tr>
                ))}</tbody>
              </table> : <table className="data-table">
                <thead><tr><th>Flow</th><th>First frame</th><th>Last frame</th><th>Packets</th><th>Bytes</th></tr></thead>
                <tbody>{pages.flows.entries.map((entry) => (
                  <tr key={entry.stream_id} className="cursor-pointer" onClick={() => { setTab("packets"); void inspect(entry.first_packet_index); }}>
                    <td className="max-w-80 truncate" title={entry.stream_id}>{entry.stream_id}</td>
                    <td>{entry.first_packet_index}</td><td>{entry.last_packet_index}</td><td>{entry.packet_count}</td><td>{entry.captured_bytes}</td>
                  </tr>
                ))}</tbody>
              </table>}
              {!page.entries.length && <EmptyState title="No observations returned" detail="Only real completed capture data is displayed." />}
            </div>
            <div className="flex shrink-0 items-center justify-between border-y border-line px-3 py-1 text-xs text-fg-muted">
              <span>{page.total ? String(page.offset + 1) + "–" + String(page.offset + page.entries.length) + " of " + String(page.total) : "No rows"}</span>
              <div className="flex gap-1">
                <ToolButton disabled={loadingPages || page.offset === 0} onClick={() => movePage(-1)}>Previous</ToolButton>
                <ToolButton disabled={loadingPages || page.offset + SIZE >= page.total} onClick={() => movePage(1)}>Next</ToolButton>
              </div>
            </div>
            <Pane className="max-h-[32%] shrink-0" title={selectedIndex === null ? "Original captured frame" : "Original frame #" + selectedIndex}
              actions={frame && frame.offset + frame.bytes.length < frame.frame_length ?
                <ToolButton onClick={() => void inspect(frame.index, frame.offset + frame.bytes.length)}>Next 4 KiB</ToolButton> : undefined}>
              {frame ? <div className="p-2">
                <div className="mb-1 text-[10px] text-fg-muted">Frame {frame.index} · offset {frame.offset} · {frame.bytes.length} / {frame.frame_length} bytes</div>
                <pre className="overflow-auto whitespace-pre font-mono text-[11px] text-fg-dim">{bytesAsHex(frame.bytes, frame.offset)}</pre>
              </div> : <EmptyState title="Select a captured packet" detail="Inspect byte-exact original frames in bounded 4 KiB pages." />}
            </Pane>
          </>
        ) : <EmptyState title={running ? "Capturing native frames…" : "No completed live capture"}
          detail={running ? "The Rust capture session keeps running during navigation. Return here for status and original frames." :
            "Select an Ethernet interface and saved case, confirm the native consent prompt and capture. Linux raw-socket permission is required."} />}
      </div>
    </div>
  );
}

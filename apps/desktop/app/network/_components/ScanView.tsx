"use client";
/** Case-authorized native TCP/UDP scan observations via Rust. */
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import {
  FileJson, FileSpreadsheet, Laptop, Play, Radar, Save, Square, Trash2, Upload,
} from "lucide-react";
import { EmptyState, Pane, Resizer, Select, TextInput, ToolButton } from "@ds/panes";
import { IconButton, InfoTip, StatusStrip } from "@ds/compact";
import {
  isDesktop,
  netscanExport,
  netscanDiscoverHosts,
  netscanArpDiscoverV1,
  netscanNdpDiscoverV1,
  netscanNdpStopV1,
  netscanIcmpDiscoverV1,
  netscanIcmp6DiscoverV1,
  netscanServiceChecksV1,
  netscanTraceIpv4V1,
  type ServiceChecksWire,
  netscanTraceIpv6V1,
  type TraceHopV6Wire,
  netscanIcmpStopV1,
  netscanSynStartV1,
  netscanSyn6StartV1,
  netscanSynStopV1,
  netscanArpStopV1,
  captureInterfacesV1,
  networkRuntimeCapabilitiesV1,
  type NetworkRuntimeCapabilitiesV1,
  netscanResults,
  netscanObservationsV1,
  netscanStart,
  netscanUdpStartV1,
  netscanStatus,
  netscanStop,
  type ScanEntryWire,
  type ArpNeighborWire,
  type SynFindingWire,
  type IcmpObservationWire,
  type TraceHopWire,
  type CaptureInterfaceV1,
  type ScanObservationPageWire,
  type ScanProgressWire,
  type NetscanStatusWire,
  netscanProfileSaveV1,
  netscanProfileListV1,
  netscanProfileDeleteV1,
  type ScanProfileWire,
} from "@lib/ipc";
import { useWorkbench, useWorkbenchCase } from "@state/workbench";
import { AuthorizedCaseAction } from "@/app/_components/AuthorizedCaseAction";
import { useWorkspaceDraft } from "@state/workspace-sessions";
import { invoke, Channel } from "@tauri-apps/api/core";

const PORT_PRESETS = [
  { value: "top25", label: "Top 25 ports" },
  { value: "top100", label: "Top 100 ports" },
  { value: "1-1024", label: "Well known (1-1024)" },
];

// --- scan-depth slice: raw scan types + service probes ------------------------
// Typed local wrappers for the scan-depth commands. The canonical clients live
// in lib/ipc.ts; these stay module-private so the view works before that
// centralization lands. Same shape as the existing netscan_* clients above.

type StealthScanTypeWire = "fin" | "null" | "xmas" | "ack" | "window";
const STEALTH_SCAN_TYPES: { value: StealthScanTypeWire; label: string }[] = [
  { value: "fin", label: "TCP FIN" },
  { value: "null", label: "TCP NULL" },
  { value: "xmas", label: "TCP Xmas" },
  { value: "ack", label: "TCP ACK" },
  { value: "window", label: "TCP Window" },
];

interface StealthFindingWire {
  host: string;
  port: number;
  scan: string;
  state: "open" | "closed" | "unfiltered" | "filtered" | "open_filtered";
  reason: string;
  elapsed_ms: number;
}

async function netscanStealthStartV1(
  scanType: StealthScanTypeWire,
  targets: string,
  ports: string,
  authorized: boolean,
  caseId: string,
  interfaceName: string,
  onProgress?: (p: ScanProgressWire) => void,
): Promise<StealthFindingWire[]> {
  if (!isDesktop()) throw new Error("Raw scan types require the desktop runtime");
  const channel = new Channel<ScanProgressWire>();
  if (onProgress) channel.onmessage = onProgress;
  return invoke<StealthFindingWire[]>("netscan_stealth_start_v1", {
    scanType, targets, ports, authorized, caseId, interfaceName, onProgress: channel,
  });
}

async function netscanStealthStopV1(): Promise<boolean> {
  if (!isDesktop()) throw new Error("Raw scan cancellation requires the desktop runtime");
  return invoke<boolean>("netscan_stealth_stop_v1", {});
}

interface ServiceProbeResultWire {
  host: string;
  port: number;
  service_claim: string;
  basis: "banner" | "probe_response" | "none";
  confidence: "high" | "medium" | "low";
  probe_used: string;
  soft_match: boolean;
  raw_excerpt_trimmed: string;
  remote_software_claim: string | null;
  elapsed_ms: number;
}

async function netscanServiceProbeV1(
  host: string,
  port: number,
  authorized: boolean,
  caseId: string,
): Promise<ServiceProbeResultWire> {
  if (!isDesktop()) throw new Error("Service probing requires the desktop runtime");
  return invoke<ServiceProbeResultWire>("netscan_service_probe_v1", { host, port, authorized, caseId });
}

// --- os-depth II slice: saved scan profiles + timing templates ----------------

type TimingTemplateWire = "paranoid" | "sneaky" | "polite" | "normal" | "aggressive";
const TIMING_TEMPLATES: { value: TimingTemplateWire; label: string }[] = [
  { value: "paranoid", label: "Paranoid (T0)" },
  { value: "sneaky", label: "Sneaky (T1)" },
  { value: "polite", label: "Polite (T2)" },
  { value: "normal", label: "Normal (T3)" },
  { value: "aggressive", label: "Aggressive (T4)" },
];

/**
 * Honesty contract for the template selector, verbatim in the tooltip. The
 * backend keeps ONE adaptive per-host latency budget (an EWMA of measured
 * probe durations clamped to TCP 300-1800 ms / UDP 300-1200 ms,
 * application/timing.rs). Only "normal" is adaptive today; the other labels
 * are recorded with saved profiles and describe how the SAME bounds will be
 * clamped once backend support lands (slower templates hold the max,
 * aggressive holds the min). Until then they change no probe behavior, and
 * the UI must never suggest otherwise.
 */
const TIMING_TOOLTIP =
  "Only Normal is adaptive today: the backend per-host budget is an EWMA of measured probe durations clamped to TCP 300-1800 ms / UDP 300-1200 ms. "
  + "Paranoid/Sneaky/Polite are recorded with the profile and would hold the max bound; Aggressive would hold the min. "
  + "Selecting them changes no probe behavior today.";

/**
 * Full §9.3 authorization wording, verbatim in the tooltip/aria-label. UX
 * revision: the toolbar shows only the compact checkbox + short label. The
 * checkbox itself cannot be dropped — every scan command takes the authorized
 * flag and the backend rejects probes without this acknowledgment.
 */
const AUTHORIZATION_TIP =
  "§9.3 — I confirm the target is mine or I have explicit authorization to assess it. "
  + "The backend verifies the selected saved case and asks for native confirmation before starting.";

/** Uniform toolbar cell: h-7 icon buttons center inside the h-8 row line. */
function IconCell({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center">
      {children}
    </span>
  );
}

export function ScanView() {
  const desktop = isDesktop();
  const [capabilities, setCapabilities] = useState<NetworkRuntimeCapabilitiesV1 | null>(null);
  const windowsHost = capabilities?.platform === "windows";
  const linuxHost = capabilities?.platform === "linux";
  useEffect(() => {
    if (!desktop) return;
    let live = true;
    void networkRuntimeCapabilitiesV1()
      .then((caps) => { if (live) setCapabilities(caps); })
      .catch((cause) => {
        if (live) setCapabilities({
          platform: "unsupported", tcp_connect: false, udp: false,
          ipv4_echo: false, ipv4_trace: false, linux_on_link: false,
          capture_backend_present: false,
          capture_detail: "Cannot query native platform capabilities: " + String(cause),
        });
      });
    return () => { live = false; };
  }, [desktop]);
  const wb = useWorkbench();
  const { caseSession } = useWorkbenchCase();
  const revision = caseSession.phase === "ready" && caseSession.caseId === wb.caseId
    ? caseSession.revision : null;
  const identity = wb.caseId + ":" + String(revision);
  const [retainedRevision, setRetainedRevision] = useWorkspaceDraft<number | null>(
    wb.caseId, "network", "scan-session-revision", null,
  );
  const [target, setTarget] = useWorkspaceDraft(wb.caseId, "network", "scan-target", "127.0.0.1");
  const [notesWidth, setNotesWidth] = useState(264);
  const [ports, setPorts] = useWorkspaceDraft(wb.caseId, "network", "scan-ports", "top25");
  const [transport, setTransport] = useWorkspaceDraft<"tcp" | "udp">(
    wb.caseId, "network", "scan-transport", "tcp",
  );
  const [authorized, setAuthorized] = useState(false);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<ScanProgressWire | null>(null);
  const [results, setResults] = useState<ScanEntryWire[]>([]);
  const [discovered, setDiscovered] = useState<string[] | null>(null);
  const [discoveryBusy, setDiscoveryBusy] = useState(false);
  const [arpInterfaces, setArpInterfaces] = useState<CaptureInterfaceV1[]>([]);
  const [arpInterface, setArpInterface] = useWorkspaceDraft(
    wb.caseId, "network", "scan-arp-interface", "",
  );
  const [arpBusy, setArpBusy] = useState(false);
  const [ndpBusy, setNdpBusy] = useState(false);
  const [icmpBusy, setIcmpBusy] = useState(false);
  const [icmpFamily, setIcmpFamily] = useState<"IPv4" | "IPv6">("IPv4");
  const [traceBusy, setTraceBusy] = useState(false);
  const [traceRows, setTraceRows] = useState<TraceHopWire[] | null>(null);
  const [icmpRows, setIcmpRows] = useState<IcmpObservationWire[] | null>(null);
  const [ndpNeighbors, setNdpNeighbors] = useState<ArpNeighborWire[] | null>(null);
  const [synBusy, setSynBusy] = useState(false);
  const [synFamily, setSynFamily] = useState<"IPv4" | "IPv6">("IPv4");
  const [synProgress, setSynProgress] = useState<ScanProgressWire | null>(null);
  const [synFindings, setSynFindings] = useState<SynFindingWire[] | null>(null);
  const [stealthType, setStealthType] = useWorkspaceDraft<StealthScanTypeWire>(
    wb.caseId, "network", "scan-depth-type", "fin",
  );
  const [stealthBusy, setStealthBusy] = useState(false);
  const [stealthProgress, setStealthProgress] = useState<ScanProgressWire | null>(null);
  const [stealthFindings, setStealthFindings] = useState<StealthFindingWire[] | null>(null);
  const [probeBusy, setProbeBusy] = useState<string | null>(null);
  const [probeResults, setProbeResults] = useState<Record<string, ServiceProbeResultWire>>({});
  // Timing template + saved profiles: session-local presets over the backend's
  // bounded in-memory store (max 32 profiles, 4 KiB parameters each). Saving
  // and loading never touches the network, so no authorization is required.
  const [timing, setTiming] = useWorkspaceDraft<TimingTemplateWire>(
    wb.caseId, "network", "scan-timing-template", "normal",
  );
  const [profiles, setProfiles] = useState<ScanProfileWire[]>([]);
  const [selectedProfile, setSelectedProfile] = useState("");
  const [profileName, setProfileName] = useState("");
  // Presentation-only: the profile-name input is revealed by the Save icon
  // button and hidden again after a successful save (or Escape).
  const [savingProfile, setSavingProfile] = useState(false);
  const [profileBusy, setProfileBusy] = useState(false);
  const [arpNeighbors, setArpNeighbors] = useState<ArpNeighborWire[] | null>(null);
  const [observationPage, setObservationPage] = useState<ScanObservationPageWire | null>(null);
  const [observationOffset, setObservationOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<NetscanStatusWire>({ running: false, results: 0, saved_findings: 0, save_error: null });
  // One case-scoped active operation at a time. Stop buttons remain enabled.
  const networkBusy = running || status.running || discoveryBusy || arpBusy ||
    ndpBusy || icmpBusy || synBusy || traceBusy || stealthBusy || probeBusy !== null;
  // Native status/results now enforce the selected case generation on every read.
  const activeCase = useRef(identity);
  activeCase.current = identity;
  const scanCase = useRef<string | null>(
    revision !== null && retainedRevision === revision ? wb.caseId : null,
  );
  scanCase.current = revision !== null && retainedRevision === revision ? wb.caseId : null;
  const scanTicket = useRef(0);
  const pollTicket = useRef(0);

  useEffect(() => {
    scanTicket.current += 1;
    pollTicket.current += 1;
    setResults([]);
    setDiscovered(null);
    setDiscoveryBusy(false);
    setArpNeighbors(null);
    setNdpNeighbors(null);
    setArpBusy(false);
    setNdpBusy(false);
    setIcmpBusy(false);
    setIcmpFamily("IPv4");
    setIcmpRows(null);
    setTraceRows(null);
    setTrace6Rows(null);
    setTraceBusy(false);
    setSynBusy(false);
    setSynFamily("IPv4");
    setSynFindings(null);
    setSynProgress(null);
    setStealthBusy(false);
    setStealthFindings(null);
    setStealthProgress(null);
    setProbeBusy(null);
    setProbeResults({});
    setObservationPage(null);
    setObservationOffset(0);
    setProgress(null);
    setError(null);
    setRunning(false);
    // Operator authorization is tied to one backend-selected case revision.
    setAuthorized(false);
    setStatus({ running: false, results: 0, saved_findings: 0, save_error: null });
    if (desktop) {
      // Profiles are session-scoped; refresh on every case re-selection and
      // silently ignore refresh failures (the store is in-memory only).
      void netscanProfileListV1()
        .then((rows) => setProfiles(rows))
        .catch(() => setProfiles([]));
    } else {
      setProfiles([]);
    }
  }, [identity, desktop]);

  useEffect(() => {
    if (!desktop) return;
    let active = true;
    void captureInterfacesV1().then((interfaces) => {
      if (active) {
        const connected = interfaces.filter((iface) => iface.ethernet && iface.up && !iface.loopback);
        setArpInterfaces(connected);
        if (!arpInterface && connected.length > 0) setArpInterface(connected[0].name);
      }
    }).catch(() => { if (active) setArpInterfaces([]); });
    return () => { active = false; };
  }, [desktop, arpInterface, setArpInterface]);

  const poll = useCallback(async () => {
    // Do not issue backend case-scoped reads while no saved case is selected.
    // A scratchpad startup must show the Create Case path, not a scan error.
    if (revision === null) return;
    const key = identity;
    const ticket = ++pollTicket.current;
    const isCurrent = () => activeCase.current === key && ticket === pollTicket.current;
    try {
      const currentStatus = await netscanStatus();
      if (!isCurrent()) return;
      setStatus(currentStatus);
      // The backend independently gates these results by selected case revision.
      const currentResults = await netscanResults();
      if (isCurrent()) setResults(currentResults);
      try {
        const page = await netscanObservationsV1(observationOffset, 100);
        if (isCurrent()) setObservationPage(page);
      } catch {
        if (isCurrent()) setObservationPage(null);
      }
    } catch (cause) {
      if (isCurrent()) setError("Scanner status unavailable: " + String(cause));
    }
  }, [identity, revision, observationOffset]);

  // Profiles are global session state (not case evidence): a failed listing
  // degrades to an empty picker instead of a scan error banner.
  const refreshProfiles = useCallback(async () => {
    if (!desktop) return;
    try {
      setProfiles(await netscanProfileListV1());
    } catch {
      setProfiles([]);
    }
  }, [desktop]);
  useEffect(() => { void refreshProfiles(); }, [refreshProfiles]);

  const saveProfile = async () => {
    const name = profileName.trim();
    if (!desktop || profileBusy || !name || !target.trim()) return;
    setProfileBusy(true);
    setError(null);
    try {
      const saved = await netscanProfileSaveV1(name, JSON.stringify({
        target, ports, transport, timing,
      }));
      setProfileName("");
      setSavingProfile(false);
      setSelectedProfile(saved.name);
      await refreshProfiles();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setProfileBusy(false);
    }
  };

  const loadSelectedProfile = () => {
    const profile = profiles.find((p) => p.name === selectedProfile);
    if (!profile) return;
    setError(null);
    // Stored parameters are an opaque JSON envelope; every field is checked
    // individually so a malformed or older profile can only be partially
    // applied, never crash the view or widen the form beyond valid values.
    try {
      const params = JSON.parse(profile.params_json) as Record<string, unknown>;
      if (typeof params.target === "string") setTarget(params.target);
      if (typeof params.ports === "string") setPorts(params.ports);
      if (params.transport === "udp" || params.transport === "tcp") setTransport(params.transport);
      if (TIMING_TEMPLATES.some((t) => t.value === params.timing)) {
        setTiming(params.timing as TimingTemplateWire);
      }
    } catch {
      setError("Saved profile parameters are not valid JSON; profile not loaded");
    }
  };

  const deleteSelectedProfile = async () => {
    if (!desktop || profileBusy || !selectedProfile) return;
    setProfileBusy(true);
    setError(null);
    try {
      await netscanProfileDeleteV1(selectedProfile);
      setSelectedProfile("");
      await refreshProfiles();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setProfileBusy(false);
    }
  };


  useEffect(() => {
    if (!desktop || revision === null) return;
    void poll();
    const timer = setInterval(() => void poll(), 900);
    return () => clearInterval(timer);
  }, [poll, desktop, revision]);

  const start = async () => {
    if (networkBusy || revision === null || !authorized) return;
    const caseId = wb.caseId;
    const key = identity;
    const ticket = ++scanTicket.current;
    pollTicket.current += 1;
    scanCase.current = caseId;
    const isCurrent = () => activeCase.current === key && scanTicket.current === ticket;
    setRunning(true);
    setError(null);
    setResults([]);
    setObservationPage(null);
    setObservationOffset(0);
    setProgress({ tried: 0, total: 0, percent: 0 });
    try {
      const launch = transport === "udp" ? netscanUdpStartV1 : netscanStart;
      await launch(target, ports, caseId, authorized, (p) => {
        if (isCurrent()) setProgress(p);
      });
      if (isCurrent()) setRetainedRevision(revision);
    } catch (err) {
      if (isCurrent()) setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (isCurrent()) {
        setRunning(false);
        setProgress(null);
        void poll();
      }
    }
  };

  const discover = async () => {
    if (!desktop || revision === null || !authorized || discoveryBusy ||
      running || status.running || synBusy || arpBusy || ndpBusy || icmpBusy || traceBusy) return;
    const key = identity;
    setError(null);
    setDiscovered(null);
    setDiscoveryBusy(true);
    try {
      const found = await netscanDiscoverHosts(target, authorized);
      if (activeCase.current === key) setDiscovered(found);
    } catch (err) {
      if (activeCase.current === key) {
        const text = err instanceof Error ? err.message : String(err);
        if (!text.includes("cancelled")) setError(text);
      }
    } finally {
      if (activeCase.current === key) setDiscoveryBusy(false);
    }
  };
  const stopDiscovery = async () => {
    try { await netscanStop(); }
    catch (err) { setError(err instanceof Error ? err.message : String(err)); }
  };

  const runSyn = async () => {
    if (networkBusy) return;
    if (!desktop || revision === null || !authorized || !arpInterface
      || synBusy || arpBusy || ndpBusy || icmpBusy || status.running || running) return;
    const key = identity;
    setError(null);
    setSynBusy(true);
    setSynFamily("IPv4");
    setSynFindings(null);
    setSynProgress({ tried: 0, total: 0, percent: 0 });
    try {
      const rows = await netscanSynStartV1(target, ports, arpInterface, true, (p) => {
        if (activeCase.current === key) setSynProgress(p);
      });
      if (activeCase.current === key) setSynFindings(rows);
    } catch (err) {
      if (activeCase.current === key) setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (activeCase.current === key) {
        setSynBusy(false);
        setSynProgress(null);
      }
    }
  };
  const runSyn6 = async () => {
    if (networkBusy) return;
    if (!desktop || revision === null || !authorized || !arpInterface ||
      synBusy || arpBusy || ndpBusy || icmpBusy || traceBusy || status.running || running) return;
    const key = identity;
    setError(null);
    setSynBusy(true);
    setSynFamily("IPv6");
    setSynFindings(null);
    setSynProgress({ tried: 0, total: 0, percent: 0 });
    try {
      const rows = await netscanSyn6StartV1(target, ports, arpInterface, true, (p) => {
        if (activeCase.current === key) setSynProgress(p);
      });
      if (activeCase.current === key) setSynFindings(rows);
    } catch (err) {
      if (activeCase.current === key) setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (activeCase.current === key) {
        setSynBusy(false);
        setSynProgress(null);
      }
    }
  };

  const stopSyn = async () => {
    try { await netscanSynStopV1(); }
    catch (err) { setError(err instanceof Error ? err.message : String(err)); }
  };

  // Raw FIN/NULL/Xmas/ACK/Window scan (Linux only). Mirrors the raw SYN flow:
  // authorization checkbox, saved case, backend native confirmation, progress
  // channel and a stop button that stays reachable for the whole run.
  const runStealth = async () => {
    if (networkBusy) return;
    if (!desktop || revision === null || !authorized || !arpInterface ||
      stealthBusy || synBusy || arpBusy || ndpBusy || icmpBusy || traceBusy ||
      status.running || running) return;
    const key = identity;
    setError(null);
    setStealthBusy(true);
    setStealthFindings(null);
    setStealthProgress({ tried: 0, total: 0, percent: 0 });
    try {
      const rows = await netscanStealthStartV1(stealthType, target, ports, true, wb.caseId, arpInterface, (p) => {
        if (activeCase.current === key) setStealthProgress(p);
      });
      if (activeCase.current === key) setStealthFindings(rows);
    } catch (err) {
      if (activeCase.current === key) setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (activeCase.current === key) {
        setStealthBusy(false);
        setStealthProgress(null);
      }
    }
  };
  const stopStealth = async () => {
    try { await netscanStealthStopV1(); }
    catch (err) { setError(err instanceof Error ? err.message : String(err)); }
  };

  // Bounded service probe of ONE observed open port. Results are keyed by
  // host:port and rendered as basis badges next to the row.
  const probeService = async (host: string, port: number) => {
    if (networkBusy) return;
    if (!desktop || revision === null || !authorized) return;
    const key = identity;
    const rowKey = host + ":" + port;
    setError(null);
    setProbeBusy(rowKey);
    try {
      const result = await netscanServiceProbeV1(host, port, true, wb.caseId);
      if (activeCase.current === key) {
        setProbeResults((previous) => ({ ...previous, [rowKey]: result }));
      }
    } catch (err) {
      if (activeCase.current === key) setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (activeCase.current === key) setProbeBusy(null);
    }
  };

  const discoverArp = async () => {
    if (networkBusy) return;
    if (!desktop || revision === null || !authorized || !arpInterface
        || running || status.running || arpBusy || ndpBusy || synBusy || icmpBusy || traceBusy) return;
    const key = identity;
    setError(null);
    setArpNeighbors(null);
    setArpBusy(true);
    try {
      const neighbors = await netscanArpDiscoverV1(target, arpInterface, true);
      if (activeCase.current === key) setArpNeighbors(neighbors);
    } catch (err) {
      if (activeCase.current === key) {
        setError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      if (activeCase.current === key) setArpBusy(false);
    }
  };

  const discoverIcmp = async () => {
    if (networkBusy) return;
    if (!desktop || revision === null || !authorized || !arpInterface ||
      running || status.running || arpBusy || ndpBusy || synBusy || icmpBusy) return;
    const key = identity;
    setError(null);
    setIcmpRows(null);
    setIcmpFamily("IPv4");
    setIcmpBusy(true);
    try {
      const rows = await netscanIcmpDiscoverV1(target, arpInterface, true);
      if (activeCase.current === key) setIcmpRows(rows);
    } catch (err) {
      if (activeCase.current === key) setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (activeCase.current === key) setIcmpBusy(false);
    }
  };
  const [trace6Rows, setTrace6Rows] = useState<TraceHopV6Wire[] | null>(null);
  const runTrace6 = async () => {
    if (networkBusy) return;
    if (!desktop || revision === null || !authorized || !arpInterface ||
      running || status.running || arpBusy || ndpBusy || synBusy || icmpBusy || traceBusy) return;
    const key = identity;
    setError(null);
    setTrace6Rows(null);
    setTraceBusy(true);
    try {
      const rows = await netscanTraceIpv6V1(target, arpInterface, 12, true);
      if (activeCase.current === key) setTrace6Rows(rows);
    } catch (err) {
      if (activeCase.current === key) setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (activeCase.current === key) setTraceBusy(false);
    }
  };
  const runTrace = async () => {
    if (networkBusy) return;
    if (!desktop || revision === null || !authorized || !arpInterface ||
      running || status.running || arpBusy || ndpBusy || synBusy || icmpBusy || traceBusy) return;
    const key = identity;
    setError(null);
    setTraceRows(null);
    setTraceBusy(true);
    try {
      const rows = await netscanTraceIpv4V1(target, arpInterface, 12, true);
      if (activeCase.current === key) setTraceRows(rows);
    } catch (err) {
      if (activeCase.current === key) setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (activeCase.current === key) setTraceBusy(false);
    }
  };
  const stopTrace = async () => {
    try { await netscanIcmpStopV1(); }
    catch (err) { setError(err instanceof Error ? err.message : String(err)); }
  };

  const discoverIcmp6 = async () => {
    if (networkBusy) return;
    if (!desktop || revision === null || !authorized || !arpInterface ||
      running || status.running || arpBusy || ndpBusy || synBusy || icmpBusy || traceBusy) return;
    const key = identity;
    setError(null);
    setIcmpRows(null);
    setIcmpFamily("IPv6");
    setIcmpBusy(true);
    try {
      const rows = await netscanIcmp6DiscoverV1(target, arpInterface, true);
      if (activeCase.current === key) setIcmpRows(rows);
    } catch (err) {
      if (activeCase.current === key) setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (activeCase.current === key) setIcmpBusy(false);
    }
  };

  const stopIcmp = async () => {
    try { await netscanIcmpStopV1(); }
    catch (err) { setError(err instanceof Error ? err.message : String(err)); }
  };

  const discoverNdp = async () => {
    if (networkBusy) return;
    if (!desktop || revision === null || !authorized || !arpInterface ||
      running || status.running || arpBusy || synBusy || ndpBusy) return;
    const key = identity;
    setError(null);
    setNdpNeighbors(null);
    setNdpBusy(true);
    try {
      const rows = await netscanNdpDiscoverV1(target, arpInterface, true);
      if (activeCase.current === key) setNdpNeighbors(rows);
    } catch (err) {
      if (activeCase.current === key) setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (activeCase.current === key) setNdpBusy(false);
    }
  };
  const stopNdp = async () => {
    try { await netscanNdpStopV1(); }
    catch (err) { setError(err instanceof Error ? err.message : String(err)); }
  };

  const stopArp = async () => {
    try { await netscanArpStopV1(); }
    catch (err) { setError(err instanceof Error ? err.message : String(err)); }
  };

  const stop = async () => {
    if (scanCase.current !== wb.caseId && !status.running) return;
    try {
      await netscanStop();
      void poll();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  // NSE-lite: run the bounded banner-check registry over one probed open
  // port. Findings are advisory evidence lines, never verdicts.
  const [checkResults, setCheckResults] = useState<Record<string, ServiceChecksWire>>({});
  const runChecks = async (host: string, port: number) => {
    if (networkBusy) return;
    if (!desktop || revision === null || !authorized) return;
    const key = identity;
    const rowKey = host + ":" + port;
    setError(null);
    setProbeBusy(rowKey);
    try {
      const wire = await netscanServiceChecksV1(host, port, true, wb.caseId);
      if (activeCase.current === key) {
        setCheckResults((previous) => ({ ...previous, [rowKey]: wire }));
      }
    } catch (err) {
      if (activeCase.current === key) setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (activeCase.current === key) setProbeBusy(null);
    }
  };

  const openCount = observationPage?.open ?? results.filter((r) => r.state === "open").length;
  const observedCount = observationPage?.total ?? results.length;

  // One Probe cell shared by both table branches: a per-host "probe service"
  // button on open rows, then the result as an evidence-basis badge. Claims
  // are always labeled as unverified remote assertions.
  const probeCell = (host: string, port: number, open: boolean) => {
    if (!open) return <td className="text-fg-muted">—</td>;
    const rowKey = host + ":" + port;
    const result = probeResults[rowKey];
    if (probeBusy === rowKey) {
      return <td className="text-fg-muted">probing…</td>;
    }
    if (result) {
      const tone = result.confidence === "high" ? "text-ok"
        : result.confidence === "medium" ? "text-orange" : "text-fg-muted";
      const checks = checkResults[rowKey];
      return (
        <td className={tone} title={"basis: " + result.basis + " · probe: " + result.probe_used +
          (result.raw_excerpt_trimmed ? " · excerpt: " + result.raw_excerpt_trimmed : "")}>
          {result.basis === "none" ? "no claim" : result.service_claim + " · " + result.basis}
          {result.remote_software_claim ? (
            <span className="text-fg-muted" title="Unverified software identity claimed by the remote server">
              {" "}· claims {result.remote_software_claim}
            </span>
          ) : null}
          {checks ? (
            <span className="block font-mono text-[10px] text-fg-muted">
              {checks.findings.length === 0
                ? "checks: none fired"
                : checks.findings.map((f) => (
                    <span key={f.check} className="block"
                      title={f.severity + " · " + f.evidence}>
                      check {f.check} ({f.severity})
                    </span>
                  ))}
            </span>
          ) : (
            <ToolButton onClick={() => void runChecks(host, port)}
              disabled={networkBusy || !desktop || revision === null || !authorized}
              title="Run the bounded NSE-lite banner checks over a fresh probe of this port; findings are advisory evidence lines">
              run checks
            </ToolButton>
          )}
        </td>
      );
    }
    return (
      <td>
        <ToolButton onClick={() => void probeService(host, port)}
          disabled={networkBusy || !desktop || revision === null || !authorized}
          title="Bounded service probe: banner read plus protocol probes of this open port; every claim is an unverified remote assertion">
          probe service
        </ToolButton>
      </td>
    );
  };

  const exportResults = async (format: "json" | "csv") => {
    if (results.length === 0) return;
    const caseId = wb.caseId;
    setError(null);
    try {
      const path = await netscanExport(format);
      if (activeCase.current === identity) wb.logConsole(`scan exported for case ${caseId}: ${path}`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message !== "cancelled" && activeCase.current === identity) setError(message);
    }
  };
  const isPreset = PORT_PRESETS.some((p) => p.value === ports);

  // Platform availability, one hover away (Laptop icon) instead of prose rows.
  // Verbatim from the former Notes paragraph plus the availability sentence.
  const platformNote = windowsHost
    ? "Windows: TCP connect and bounded UDP scanning; IPv4 Ping and Trace use the Windows IP Helper API and do not need the missing packet-capture driver. Select a saved case, check authorization, and confirm the operation. TCP/UDP scans do not require the capture driver. ARP, NDP, raw SYN and raw FIN/NULL/Xmas/ACK/Window scan types are Linux-only."
    : linuxHost
      ? "Linux: TCP connect, bounded UDP, and privileged native raw probes. ARP/NDP/SYN require CAP_NET_RAW and an on-link interface. UDP silence is inconclusive. All active probes require case selection and native confirmation."
      : "Native raw probes and ICMP are not available on this platform. Raw FIN/NULL/Xmas/ACK/Window scan types require Linux. TCP/UDP connect scans remain supported. " + (capabilities?.capture_detail ?? "Reading native capabilities…");

  // Status strip instead of a full-width counter bar or toolbar chips: it
  // renders only when there is something to count or an active operation.
  const statusItems: readonly ({ label: string; tone?: "muted" | "orange" | "ok" | "err" } | null)[] = [
    running || status.running
      ? { label: running ? "scan running" : "other session running", tone: "orange" }
      : null,
    observedCount > 0 || openCount > 0
      ? { label: `${observedCount} observed · ${openCount} open · ${observationPage?.closed ?? 0} closed · ${observationPage?.inconclusive ?? 0} inconclusive` }
      : null,
    scanCase.current === wb.caseId && (status.results > 0 || status.saved_findings > 0)
      ? { label: `${status.results} stored results · ${status.saved_findings} case findings` }
      : null,
    profiles.length > 0
      ? { label: `${profiles.length}/32 profiles · session-local` }
      : null,
  ];

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 flex-wrap items-center gap-2 px-2 py-1.5">
        <label className="flex cursor-pointer items-center gap-1.5 text-xs text-fg-dim">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            className="accent-[var(--color-orange)]"
            aria-label="I am authorized to assess this target"
          />
          <span>I am authorized to assess this target</span>
        </label>
        <InfoTip text={AUTHORIZATION_TIP} />
        <TextInput value={target} onChange={setTarget} placeholder="IP, CIDR, !exclusion" ariaLabel="Scan target" className="w-52" />
        <Select
          value={transport}
          onChange={(value) => setTransport(value === "udp" ? "udp" : "tcp")}
          options={[{ value: "tcp", label: "TCP connect" }, { value: "udp", label: "UDP" }]}
          ariaLabel="Scan transport"
          className="w-28"
        />
        <Select
          value={isPreset ? ports : "custom"}
          onChange={setPorts}
          options={[
            ...PORT_PRESETS,
            ...(isPreset ? [] : [{ value: ports, label: ports || "custom" }]),
          ]}
          ariaLabel="Port selection"
          className="w-40"
        />
        {!isPreset ? (
          <TextInput value={ports} onChange={setPorts} placeholder="80,443,8000-8100" ariaLabel="Custom ports" className="w-36" />
        ) : null}
        <span title={TIMING_TOOLTIP} className="inline-flex items-center">
          <Select
            value={timing}
            onChange={(value) => setTiming(value as TimingTemplateWire)}
            options={TIMING_TEMPLATES}
            ariaLabel="Timing template"
            className="w-36"
          />
        </span>
        <Select
          value={selectedProfile}
          onChange={setSelectedProfile}
          options={[
            { value: "", label: "No profile selected" },
            ...profiles.map((profile) => ({ value: profile.name, label: profile.name })),
          ]}
          ariaLabel="Saved scan profile"
          className="w-40"
        />
        {status.running || (running && scanCase.current === wb.caseId) ? (
          <IconCell>
            <IconButton icon={Square} tone="danger" onClick={() => void stop()} title="Stop the active scan" />
          </IconCell>
        ) : (
          <IconCell>
            <IconButton
              icon={Play}
              tone="primary"
              onClick={() => void start()}
              disabled={!desktop || revision === null || !authorized || !target.trim() || networkBusy}
              title={revision === null ? "Select a saved native investigation case before scanning" : "Backend-selected case and native confirmation are required before network probes"}
            />
          </IconCell>
        )}
        {discoveryBusy ? (
          <IconCell>
            <IconButton icon={Square} tone="danger" onClick={() => void stopDiscovery()}
              title="Cancel the current saved-case TCP host discovery" />
          </IconCell>
        ) : (
          <IconCell>
            <IconButton
              icon={Radar}
              onClick={() => void discover()}
              disabled={!desktop || revision === null || !authorized || !target.trim() || networkBusy}
              title="Discover hosts — discover responding hosts using bounded case-authorized TCP probes"
            />
          </IconCell>
        )}
        <IconCell>
          <IconButton
            icon={Save}
            tone={savingProfile ? "primary" : "default"}
            onClick={() => { if (!savingProfile) setSavingProfile(true); else void saveProfile(); }}
            disabled={!desktop || profileBusy || !target.trim() || (savingProfile && !profileName.trim())}
            title="Save profile — saves the current target, ports, transport and timing template as a named profile. Session-local, max 32 profiles and 4 KiB of parameters each; saving never touches the network or the case store."
          />
        </IconCell>
        {savingProfile ? (
          <TextInput
            value={profileName}
            onChange={setProfileName}
            placeholder="profile name"
            ariaLabel="New profile name"
            className="w-36"
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                setProfileName("");
                setSavingProfile(false);
              }
            }}
          />
        ) : null}
        <IconCell>
          <IconButton
            icon={Upload}
            onClick={loadSelectedProfile}
            disabled={!selectedProfile || profileBusy}
            title="Load profile — loads the saved profile into target, ports, transport and timing template"
          />
        </IconCell>
        <IconCell>
          <IconButton
            icon={Trash2}
            tone="danger"
            onClick={() => void deleteSelectedProfile()}
            disabled={!selectedProfile || profileBusy}
            title="Delete profile — deletes the selected saved profile from the session-local store"
          />
        </IconCell>
        {windowsHost ? (
          <>
            <span title="Windows discovery — ICMP ping and traceroute require a connected adapter" className="inline-flex items-center">
              <Select value={arpInterface} onChange={setArpInterface}
                options={[{ value: "", label: "Select network adapter" }, ...arpInterfaces.map((iface) => ({ value: iface.name, label: iface.display_name || "Windows adapter #" + iface.index }))]}
                ariaLabel="Windows source network adapter" className="w-48" />
            </span>
            {icmpBusy ? (
              <ToolButton tone="danger" onClick={() => void stopIcmp()}
                title="Cancel active Windows ICMPv4 discovery">
                Stop
              </ToolButton>
            ) : (
              <ToolButton onClick={() => void discoverIcmp()}
                disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                  !target.trim() || running || status.running || traceBusy}
                title="Ping IPv4 — Windows IP Helper ICMPv4 Echo with native confirmation">
                Ping
              </ToolButton>
            )}
            {traceBusy ? (
              <ToolButton tone="danger" onClick={() => void stopTrace()}
                title="Cancel active Windows traceroute">
                Stop
              </ToolButton>
            ) : (
              <ToolButton onClick={() => void runTrace()}
                disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                  !target.trim() || running || status.running || icmpBusy}
                title="Trace IPv4 — Windows IP Helper IPv4 traceroute with native authorization">
                Trace 4
              </ToolButton>
            )}
            {arpInterfaces.length === 0 && <span role="status" className="font-mono text-[10px] text-fg-muted">
              No active IPv4 source adapter; TCP/UDP scans remain available.
            </span>}
          </>
        ) : linuxHost ? (
          <>
            <Select
              value={arpInterface}
              onChange={setArpInterface}
              options={[
                { value: "", label: "Choose Ethernet NIC" },
                ...arpInterfaces.map((iface) => ({
                  value: iface.name, label: iface.name,
                })),
              ]}
              ariaLabel="ARP discovery Ethernet interface"
              className="w-40"
            />
            {arpBusy ? (
              <ToolButton tone="danger" onClick={() => void stopArp()}
                title="Stop case-authorized native ARP discovery">
                Stop
              </ToolButton>
            ) : (
              <ToolButton
                onClick={() => void discoverArp()}
                disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface
                  || !target.trim() || running || status.running || ndpBusy || synBusy}
                title="ARP — Linux only: native confirmation, on-link scope, CAP_NET_RAW and case authorization required. Up to 32 on-link IPv4 hosts">
                ARP
              </ToolButton>
            )}
            {ndpBusy ? (
              <ToolButton tone="danger" onClick={() => void stopNdp()}
                title="Stop the active case-authorized NDP discovery">
                Stop
              </ToolButton>
            ) : (
              <ToolButton onClick={() => void discoverNdp()}
                disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                  !target.trim() || running || status.running || arpBusy || synBusy}
                title="NDP — Linux only: native case confirmation, selected NIC, fe80::/10 IPv6 target and CAP_NET_RAW required. 16 link-local IPv6 hosts · silence ≠ down">
                NDP
              </ToolButton>
            )}
            {traceBusy ? (
              <ToolButton tone="danger" onClick={() => void stopTrace()}
                title="Cancel the current case-scoped ICMP route trace">
                Stop
              </ToolButton>
            ) : (
              <ToolButton onClick={() => void runTrace()}
                disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                  !target.trim() || running || status.running || arpBusy || ndpBusy || synBusy || icmpBusy}
                title="Trace IPv4 — Linux or Windows: up to 12 TTL-limited ICMPv4 probes, backend confirmation and saved-case authorization required">
                Trace 4
              </ToolButton>
            )}
            {traceBusy ? null : (
              <ToolButton onClick={() => void runTrace6()}
                disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                  !target.trim() || running || status.running || arpBusy || ndpBusy || synBusy || icmpBusy}
                title="Trace IPv6 — Linux only: up to 12 hop-limited ICMPv6 probes with per-hop unicast hop limit, backend confirmation and saved-case authorization required">
                Trace 6
              </ToolButton>
            )}
            {icmpBusy ? (
              <ToolButton tone="danger" onClick={() => void stopIcmp()}
                title="Cancel the active case-scoped ICMPv4 echo discovery">
                Stop
              </ToolButton>
            ) : (
              <ToolButton onClick={() => void discoverIcmp()}
                disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                  !target.trim() || running || status.running || arpBusy || ndpBusy || synBusy}
                title="Echo IPv4 — Windows native IP Helper or Linux CAP_NET_RAW: explicitly confirmed case-scoped ICMPv4 discovery. Up to 32 hosts">
                Echo 4
              </ToolButton>
            )}
            <ToolButton onClick={() => void discoverIcmp6()}
              disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                !target.trim() || running || status.running || arpBusy || ndpBusy || synBusy || icmpBusy || traceBusy}
              title="Echo IPv6 — Linux native ICMPv6 Echo: 32 distinct fe80::/10 targets on the selected Ethernet interface, native confirmation, CAP_NET_RAW">
              Echo 6
            </ToolButton>
            {synBusy ? (
              <ToolButton tone="danger" onClick={() => void stopSyn()}
                title="Stop case-authorized raw SYN scan">
                Stop
              </ToolButton>
            ) : (
              <ToolButton onClick={() => void runSyn()}
                disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface
                  || !target.trim() || !ports.trim() || running || status.running || arpBusy}
                title="Raw SYN — Linux only: CAP_NET_RAW, selected interface, backend saved-case authorization and native confirmation required">
                SYN
              </ToolButton>
            )}
            <ToolButton onClick={() => void runSyn6()}
              disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                !target.trim() || !ports.trim() || running || status.running ||
                synBusy || arpBusy || ndpBusy || icmpBusy || traceBusy}
              title="SYN IPv6 — Linux: max 16 distinct fe80::/10 hosts, 64 ports, 512 SYN probes and 8 in flight; requires CAP_NET_RAW and native consent">
              SYN 6
            </ToolButton>
            {synProgress ? (
              <span className="font-mono text-[10px] text-fg-muted">
                SYN {synProgress.tried}/{synProgress.total} · {synProgress.percent}%
              </span>
            ) : null}
            <span
              title="Raw scan types require Linux · silence means the documented default state, not proof"
              className="inline-flex items-center"
            >
              <Select
                value={stealthType}
                onChange={(value) => setStealthType(value as StealthScanTypeWire)}
                options={STEALTH_SCAN_TYPES}
                ariaLabel="Raw scan type"
                className="w-32"
              />
            </span>
            {stealthBusy ? (
              <ToolButton tone="danger" onClick={() => void stopStealth()}
                title="Stop raw — stops the case-authorized raw FIN/NULL/Xmas/ACK/Window scan">
                Stop
              </ToolButton>
            ) : (
              <ToolButton onClick={() => void runStealth()}
                disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                  !target.trim() || !ports.trim() || running || status.running}
                title="Raw depth — Linux only: FIN/NULL/Xmas/ACK/Window flag probes with documented reply semantics; requires CAP_NET_RAW, a selected interface, a saved case and native confirmation">
                Raw
              </ToolButton>
            )}
            {stealthProgress ? (
              <span className="font-mono text-[10px] text-fg-muted">
                {stealthType} {stealthProgress.tried}/{stealthProgress.total} · {stealthProgress.percent}%
              </span>
            ) : null}
          </>
        ) : null}
        {results.length > 0 ? (
          <>
            <IconCell>
              <IconButton icon={FileJson} onClick={() => void exportResults("json")} title="Save results as JSON" />
            </IconCell>
            <IconCell>
              <IconButton icon={FileSpreadsheet} onClick={() => void exportResults("csv")} title="Save results as CSV" />
            </IconCell>
          </>
        ) : null}
        <span className="flex-1" />
        <span
          role="note"
          tabIndex={0}
          aria-label={platformNote}
          title={platformNote}
          className="inline-flex h-8 cursor-help items-center text-fg-muted hover:text-fg-dim focus-visible:outline focus-visible:outline-1 focus-visible:outline-ring"
        >
          <Laptop size={12} strokeWidth={1.5} />
        </span>
      </div>
      <StatusStrip items={statusItems} />
      {error ? <div className="border-b border-err/50 bg-err/10 px-2 py-1 font-mono text-[10px] text-err">{error}</div> : null}
      {revision === null && <AuthorizedCaseAction activity="Network scanning" />}
      <div className="flex min-h-0 flex-1 gap-px bg-line">
        <div className="flex min-w-0 flex-1 flex-col gap-px bg-line">
          <Pane title="Authorization (§9.3)" className="shrink-0">
            <label className="flex cursor-pointer items-start gap-2 p-2 text-xs leading-relaxed text-fg-dim">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                className="mt-0.5 accent-[var(--color-orange)]"
              />
              <span>
                I confirm the target is mine or I have explicit authorization to assess it. The backend verifies the selected saved case and asks for native confirmation before starting.
              </span>
            </label>
            {windowsHost ? (
              <div className="flex flex-wrap items-center gap-2 border-t border-line p-2">
                <span className="text-xs text-fg-muted">Windows discovery · TCP/UDP above; ICMP and trace below require a connected adapter</span>
                <Select value={arpInterface} onChange={setArpInterface}
                  options={[{ value: "", label: "Select network adapter" }, ...arpInterfaces.map((iface) => ({ value: iface.name, label: iface.display_name || "Windows adapter #" + iface.index }))]}
                  ariaLabel="Windows source network adapter" className="w-52" />
                {icmpBusy ? (
                  <ToolButton tone="danger" onClick={() => void stopIcmp()}
                    title="Cancel active Windows ICMPv4 discovery">
                    <Square size={11} /> Stop ping
                  </ToolButton>
                ) : (
                  <ToolButton onClick={() => void discoverIcmp()}
                    disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                      !target.trim() || running || status.running || traceBusy}
                    title="Windows IP Helper ICMPv4 Echo with native confirmation">
                    Ping IPv4
                  </ToolButton>
                )}
                {traceBusy ? (
                  <ToolButton tone="danger" onClick={() => void stopTrace()}
                    title="Cancel active Windows traceroute">
                    <Square size={11} /> Stop trace
                  </ToolButton>
                ) : (
                  <ToolButton onClick={() => void runTrace()}
                    disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                      !target.trim() || running || status.running || icmpBusy}
                    title="Windows IP Helper IPv4 traceroute with native authorization">
                    Trace IPv4
                  </ToolButton>
                )}
                <span className="text-xs text-fg-muted">TCP/UDP scans do not require the capture driver. ARP, NDP, raw SYN and raw FIN/NULL/Xmas/ACK/Window scan types are Linux-only.</span>
                {arpInterfaces.length === 0 && <span role="status" className="text-xs text-fg-muted">
                  No active IPv4 source adapter. TCP/UDP scans remain available above.
                </span>}
              </div>
            ) : linuxHost ? (
            <div className="flex flex-wrap items-center gap-2 border-t border-line p-2">
              <span className="font-mono text-[10px] text-fg-muted">Linux on-link discovery</span>
              <Select
                value={arpInterface}
                onChange={setArpInterface}
                options={[
                  { value: "", label: "Choose Ethernet NIC" },
                  ...arpInterfaces.map((iface) => ({
                    value: iface.name, label: iface.name,
                  })),
                ]}
                ariaLabel="ARP discovery Ethernet interface"
                className="w-44"
              />
              {arpBusy ? (
                <ToolButton tone="danger" onClick={() => void stopArp()}
                  title="Stop case-authorized native ARP discovery">
                  <Square size={11} /> Stop ARP
                </ToolButton>
              ) : (
                <ToolButton
                  onClick={() => void discoverArp()}
                  disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface
                    || !target.trim() || running || status.running || ndpBusy || synBusy}
                  title="Linux only: native confirmation, on-link scope, CAP_NET_RAW and case authorization required">
                  Discover ARP
                </ToolButton>
              )}
              <span className="font-mono text-[10px] text-fg-muted">
                ARP: up to 32 on-link IPv4 hosts
              </span>
              {ndpBusy ? (
                <ToolButton tone="danger" onClick={() => void stopNdp()}>
                  <Square size={11} /> Stop NDP
                </ToolButton>
              ) : (
                <ToolButton onClick={() => void discoverNdp()}
                  disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                    !target.trim() || running || status.running || arpBusy || synBusy}
                  title="Linux only: native case confirmation, selected NIC, fe80::/10 IPv6 target and CAP_NET_RAW required">
                  Discover NDP
                </ToolButton>
              )}
              <span className="font-mono text-[10px] text-fg-muted">
                NDP: 16 link-local IPv6 hosts · silence ≠ down
              </span>
              {traceBusy ? (
                <ToolButton tone="danger" onClick={() => void stopTrace()}
                  title="Cancel the current case-scoped ICMP route trace">
                  <Square size={11} /> Stop trace
                </ToolButton>
              ) : (
                <ToolButton onClick={() => void runTrace()}
                  disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                    !target.trim() || running || status.running || arpBusy || ndpBusy || synBusy || icmpBusy}
                  title="Linux or Windows: up to 12 TTL-limited ICMPv4 probes, backend confirmation and saved-case authorization required">
                  Trace IPv4
                </ToolButton>
              )}
              {traceBusy ? null : (
                <ToolButton onClick={() => void runTrace6()}
                  disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                    !target.trim() || running || status.running || arpBusy || ndpBusy || synBusy || icmpBusy}
                  title="Linux only: up to 12 hop-limited ICMPv6 probes with per-hop unicast hop limit, backend confirmation and saved-case authorization required">
                  Trace IPv6
                </ToolButton>
              )}
              {icmpBusy ? (
                <ToolButton tone="danger" onClick={() => void stopIcmp()}>
                  <Square size={11} /> Stop ICMP
                </ToolButton>
              ) : (
                <ToolButton onClick={() => void discoverIcmp()}
                  disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                    !target.trim() || running || status.running || arpBusy || ndpBusy || synBusy}
                  title="Windows native IP Helper or Linux CAP_NET_RAW: explicitly confirmed case-scoped ICMPv4 discovery">
                  ICMP Echo
                </ToolButton>
              )}
              <span className="font-mono text-[10px] text-fg-muted">
                ICMPv4: up to 32 hosts
              </span>
              <ToolButton onClick={() => void discoverIcmp6()}
                disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                  !target.trim() || running || status.running || arpBusy || ndpBusy || synBusy || icmpBusy || traceBusy}
                title="Linux native ICMPv6 Echo: 32 distinct fe80::/10 targets on the selected Ethernet interface, native confirmation, CAP_NET_RAW">
                IPv6 Echo
              </ToolButton>
              {synBusy ? (
                <ToolButton tone="danger" onClick={() => void stopSyn()} title="Stop case-authorized raw SYN scan">
                  <Square size={11} /> Stop SYN
                </ToolButton>
              ) : (
                <ToolButton onClick={() => void runSyn()}
                  disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface
                    || !target.trim() || !ports.trim() || running || status.running || arpBusy}
                  title="Linux only: CAP_NET_RAW, selected interface, backend saved-case authorization and native confirmation required">
                  <Play size={11} /> Raw SYN
                </ToolButton>
              )}
              <ToolButton onClick={() => void runSyn6()}
                disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                  !target.trim() || !ports.trim() || running || status.running ||
                  synBusy || arpBusy || ndpBusy || icmpBusy || traceBusy}
                title="Linux: max 16 distinct fe80::/10 hosts, 64 ports, 512 SYN probes and 8 in flight; requires CAP_NET_RAW and native consent">
                IPv6 SYN
              </ToolButton>
              {synProgress ? (
                <span className="font-mono text-[10px] text-fg-muted">
                  SYN {synProgress.tried}/{synProgress.total} · {synProgress.percent}%
                </span>
              ) : null}
              <span className="font-mono text-[10px] uppercase text-fg-muted">raw depth</span>
              <Select
                value={stealthType}
                onChange={(value) => setStealthType(value as StealthScanTypeWire)}
                options={STEALTH_SCAN_TYPES}
                ariaLabel="Raw scan type"
                className="w-36"
              />
              {stealthBusy ? (
                <ToolButton tone="danger" onClick={() => void stopStealth()}
                  title="Stop the case-authorized raw FIN/NULL/Xmas/ACK/Window scan">
                  <Square size={11} /> Stop raw
                </ToolButton>
              ) : (
                <ToolButton onClick={() => void runStealth()}
                  disabled={!desktop || !authorized || networkBusy || revision === null || !arpInterface ||
                    !target.trim() || !ports.trim() || running || status.running}
                  title="Linux only: FIN/NULL/Xmas/ACK/Window flag probes with documented reply semantics; requires CAP_NET_RAW, a selected interface, a saved case and native confirmation">
                  <Play size={11} /> Raw depth
                </ToolButton>
              )}
              <span className="font-mono text-[10px] text-fg-muted">
                Raw scan types require Linux · silence means the documented default state, not proof
              </span>
              {stealthProgress ? (
                <span className="font-mono text-[10px] text-fg-muted">
                  {stealthType} {stealthProgress.tried}/{stealthProgress.total} · {stealthProgress.percent}%
                </span>
              ) : null}
            </div>
            ) : (
              <div role="status" className="border-t border-line p-3 text-xs text-fg-muted">
                Native raw probes and ICMP are not available on this platform.
                Raw FIN/NULL/Xmas/ACK/Window scan types require Linux. TCP/UDP connect
                scans remain supported. {capabilities?.capture_detail ?? "Reading native capabilities…"}
              </div>
            )}
          </Pane>
          {progress ? (
            <div className="shrink-0 border-b border-line bg-panel px-2 py-1.5">
              <div className="mb-0.5 flex items-center justify-between font-mono text-[10px] text-fg-muted">
                <span>{progress.tried} / {progress.total} probes</span>
                <span>{progress.percent}%</span>
              </div>
              <div className="h-1.5 w-full border border-line bg-app">
                <div className="h-full bg-orange" style={{ width: `${progress.percent}%` }} />
              </div>
            </div>
          ) : null}
          <Pane title={"Network observations: " + observedCount + " · " + openCount + " open · " + (observationPage?.closed ?? 0) + " closed · " + (observationPage?.inconclusive ?? 0) + " inconclusive"} className="min-h-0 flex-1">
            {results.length === 0 && !observationPage?.entries.length ? (
              <EmptyState
                title={running ? "Scanning…" : revision === null ? "Create a case to begin" : !authorized ? "Confirm the authorized target" : "Ready to scan"}
                detail={revision === null
                  ? "Create or select a saved case above. This enables the scan controls without starting network traffic."
                  : !authorized
                    ? "Review the scope authorization checkbox, then select TCP or UDP and Run scan. A native confirmation is required."
                    : "Enter an authorized host, choose ports and press Run scan. Results, including closed and inconclusive observations, appear here."}
                badge="TCP / UDP"
              />
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th className="w-40">Host</th>
                    <th className="w-16">Port</th>
                    <th className="w-16">Proto</th>
                    <th className="w-20">State</th>
                    <th className="w-28">Service</th>
                    <th>Banner</th>
                    <th>Reason / evidence</th>
                    <th>Elapsed</th>
                    <th className="w-32">Probe</th>
                  </tr>
                </thead>
                <tbody>
                  {observationPage
                    ? observationPage.entries.map((r, i) => (
                      <tr key={"obs-" + r.host + "-" + r.port + "-" + i}>
                        <td className="text-fg">{r.host}</td>
                        <td>{r.port}</td>
                        <td className="uppercase text-fg-muted">{r.protocol}</td>
                        <td className={r.state === "open" ? "text-ok" : "text-fg-muted"}>{r.state}</td>
                        <td className="text-orange" title={r.service_basis}>{r.service}{r.service_basis === "port_hint_only" ? " (port hint)" : ""}{r.remote_software_claim ? <span title="Unverified software identity claimed by the remote server"> · claims {r.remote_software_claim}</span> : null}</td>
                        <td className="truncate text-fg-muted" title={r.banner}>{r.banner || "—"}</td>
                        <td className="text-fg-muted" title={"Method: " + r.method + "; attempts: " + r.attempts + "; retries: " + r.retries + "; OS error: " + (r.os_error_code ?? "n/a")}>{r.reason}</td>
                        <td>{r.elapsed_ms} ms</td>
                        {probeCell(r.host, r.port, r.state === "open")}
                      </tr>
                    ))
                    : results.map((r, i) => (
                      <tr key={"open-" + r.host + "-" + r.port + "-" + i}>
                        <td className="text-fg">{r.host}</td>
                        <td>{r.port}</td>
                        <td className="uppercase text-fg-muted">tcp</td>
                        <td className="text-ok">{r.state}</td>
                        <td className="text-orange">{r.service}</td>
                        <td className="truncate text-fg-muted" title={r.banner}>{r.banner}</td>
                        <td>—</td><td>—</td>
                        {probeCell(r.host, r.port, r.state === "open")}
                      </tr>
                    ))}
                </tbody>
              </table>
            )}
          </Pane>
          {observationPage && observationPage.total > 100 && (
            <div className="flex shrink-0 items-center gap-2 border-t border-line px-3 py-1 text-xs text-fg-muted">
              <ToolButton disabled={observationOffset === 0} onClick={() => setObservationOffset(Math.max(0, observationOffset - 100))}>Previous</ToolButton>
              <span>{observationPage.offset + 1}–{Math.min(observationPage.offset + observationPage.shown, observationPage.total)} / {observationPage.total}</span>
              <ToolButton disabled={observationOffset + observationPage.shown >= observationPage.total} onClick={() => setObservationOffset(observationOffset + 100)}>Next</ToolButton>
            </div>
          )}
        </div>
        <Resizer direction="horizontal" flip ariaLabel="Resize scan notes" value={notesWidth} onChange={setNotesWidth} min={220} max={500} />
        <Pane title="Notes" className="shrink-0" style={{ width: notesWidth }}>
          <div className="p-2 font-mono text-[10px] leading-relaxed text-fg-muted">
            {windowsHost
              ? "Windows: TCP connect and bounded UDP scanning; IPv4 Ping and Trace use the Windows IP Helper API and do not need the missing packet-capture driver. Select a saved case, check authorization, and confirm the operation."
              : "Linux: TCP connect, bounded UDP, and privileged native raw probes. ARP/NDP/SYN require CAP_NET_RAW and an on-link interface. UDP silence is inconclusive. All active probes require case selection and native confirmation."}
          </div>
          <div className="border-t border-line px-2 py-1.5 font-mono text-[10px] text-fg-muted">
            {scanCase.current === wb.caseId
              ? `status: ${status.running ? "scan running" : "idle"} · ${status.results} stored results · ${status.saved_findings} case findings`
              : "Native scan status is global; results and findings withheld until a scan is started in this case"}
          </div>
          {status.save_error ? <div className="border-t border-line p-2 text-xs text-err">Case save failed: {status.save_error}</div> : null}
          {synFindings !== null ? (
            <div className="border-t border-line p-2 text-[10px] text-fg-muted">
              <div className="mb-1 font-semibold text-fg">
                Correlated {synFamily} TCP SYN: {synFindings.length} observations · {synFindings.filter((r) => r.state === "open").length} open
              </div>
              <div className="max-h-36 overflow-y-auto font-mono">
                {synFindings.map((r) => (
                  <div key={r.host + ":" + r.port}>
                    {r.host}:{r.port} · {r.state} · {r.reason} · {r.elapsed_ms} ms
                  </div>
                ))}
              </div>
            </div>
          ) : null}
          {stealthFindings !== null ? (
            <div className="border-t border-line p-2 text-[10px] text-fg-muted">
              <div className="mb-1 font-semibold text-fg">
                Raw {stealthType} scan: {stealthFindings.length} observations · {stealthFindings.filter((r) => r.state === "open").length} open · {stealthFindings.filter((r) => r.state === "open_filtered").length} open|filtered
              </div>
              <div className="max-h-36 overflow-y-auto font-mono">
                {stealthFindings.map((r) => (
                  <div key={r.host + ":" + r.port + ":" + r.scan}>
                    {r.host}:{r.port} · {r.scan} · {r.state} · {r.reason} · {r.elapsed_ms} ms
                  </div>
                ))}
              </div>
              <div className="text-fg-muted">
                States classify one probe each; FIN/NULL/Xmas silence is open|filtered and ACK/Window silence is filtered by definition.
              </div>
            </div>
          ) : null}
          {trace6Rows !== null ? (
            <div>
              <p className="font-mono text-[10px] text-fg-muted">
                Native IPv6 ICMPv6 route trace: {trace6Rows.length} observed hop-limit steps
              </p>
              {trace6Rows.map((hop) => (
                <p key={hop.hop} className="font-mono text-[11px]">
                  hop {hop.hop}: {hop.responder ?? "no response"}
                  {hop.reached ? " — destination reached" : ""} ({hop.elapsed_ms} ms, {hop.reason})
                </p>
              ))}
            </div>
          ) : null}
          {traceRows !== null ? (
            <div className="border-t border-line p-2 text-[10px] text-fg-muted">
              <div className="mb-1 font-semibold text-fg">
                Native IPv4 ICMP route trace: {traceRows.length} observed TTL steps
              </div>
              <div className="max-h-36 overflow-y-auto font-mono">
                {traceRows.map((hop) => (
                  <div key={hop.ttl}>
                    TTL {hop.ttl} · {hop.responder ?? "no response"} · {hop.reason}
                    {" · "}{hop.elapsed_ms} ms{hop.reached ? " · reached" : ""}
                  </div>
                ))}
              </div>
              <div className="text-fg-muted">Router identities are not authenticated; missing responses do not prove missing hops.</div>
            </div>
          ) : null}
          {icmpRows !== null ? (
            <div className="border-t border-line p-2 text-[10px] text-fg-muted">
              <div className="mb-1 font-semibold text-fg">
                {icmpFamily} ICMP echo: {icmpRows.filter((r) => r.state === "responded").length} responding / {icmpRows.length} checked
              </div>
              <div className="max-h-28 overflow-y-auto font-mono">
                {icmpRows.map((row) => (
                  <div key={row.host}>
                    {row.host} · {row.state} · {row.reason} · {row.elapsed_ms} ms
                  </div>
                ))}
              </div>
            </div>
          ) : null}
          {ndpNeighbors !== null ? (
            <div className="border-t border-line p-2 text-[10px] text-fg-muted">
              <div className="mb-1 font-semibold text-fg">
                Correlated IPv6 Neighbor Advertisements: {ndpNeighbors.length}
              </div>
              <div className="max-h-28 overflow-y-auto font-mono">
                {ndpNeighbors.length === 0
                  ? "No matching IPv6 Neighbor Advertisements observed; silence is not proof a host is down."
                  : ndpNeighbors.map((row) => (
                    <div key={row.host}>{row.host} · {row.mac} · {row.elapsed_ms} ms</div>
                  ))}
              </div>
            </div>
          ) : null}
          {arpNeighbors !== null ? (
            <div className="border-t border-line p-2 text-[10px] text-fg-muted">
              <div className="mb-1 font-semibold text-fg">
                Correlated ARP neighbors: {arpNeighbors.length}
              </div>
              <div className="max-h-28 overflow-y-auto font-mono">
                {arpNeighbors.length === 0
                  ? "No matched ARP replies were observed. Silence does not prove hosts are down."
                  : arpNeighbors.map((row) => (
                    <div key={row.host}>{row.host} · {row.mac} · {row.elapsed_ms} ms</div>
                  ))}
              </div>
            </div>
          ) : null}
          {discovered !== null ? (
            <div className="border-t border-line p-2 text-[10px] text-fg-muted">
              <div className="mb-1 font-semibold text-fg">Responsive hosts: {discovered.length}</div>
              <div className="max-h-24 overflow-y-auto font-mono">
                {discovered.length === 0
                  ? "No TCP response on the checked discovery ports; this does not prove hosts are down."
                  : discovered.slice(0, 50).join(", ")}
                {discovered.length > 50 ? " · " + (discovered.length - 50) + " more" : ""}
              </div>
            </div>
          ) : null}

          <div className="border-t border-line p-2">
            <span className="text-fg-muted">Live scan status appears above; completed scans are listed below.</span>
          </div>
          <div className="border-t border-line p-2 text-[10px] text-fg-muted">
            Scan results, findings and Stop are bound to the backend-selected case generation; switching cases revokes stale read access.
          </div>
        </Pane>
      </div>
    </div>
  );
}

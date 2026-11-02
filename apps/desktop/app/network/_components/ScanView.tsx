"use client";
/** Case-authorized native TCP/UDP scan observations via Rust. */
import { useCallback, useEffect, useRef, useState } from "react";
import { Play, Square } from "lucide-react";
import { Chip, EmptyState, Pane, Resizer, Select, TextInput, ToolButton } from "@ds/panes";
import {
  isDesktop,
  netscanExport,
  netscanDiscoverHosts,
  netscanArpDiscoverV1,
  netscanNdpDiscoverV1,
  netscanNdpStopV1,
  netscanIcmpDiscoverV1,
  netscanIcmpStopV1,
  netscanSynStartV1,
  netscanSynStopV1,
  netscanArpStopV1,
  captureInterfacesV1,
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
  type CaptureInterfaceV1,
  type ScanObservationPageWire,
  type ScanProgressWire,
  type NetscanStatusWire,
} from "@lib/ipc";
import { useWorkbench, useWorkbenchCase } from "@state/workbench";
import { useWorkspaceDraft } from "@state/workspace-sessions";

const PORT_PRESETS = [
  { value: "top25", label: "Top 25 ports" },
  { value: "top100", label: "Top 100 ports" },
  { value: "1-1024", label: "Well known (1-1024)" },
];

export function ScanView() {
  const desktop = isDesktop();
  const wb = useWorkbench();
  const { caseSession } = useWorkbenchCase();
  const revision = caseSession.phase === "ready" && caseSession.caseId === wb.caseId
    ? caseSession.revision : null;
  const identity = wb.caseId + ":" + String(revision);
  const [retainedRevision, setRetainedRevision] = useWorkspaceDraft<number | null>(
    wb.caseId, "network", "scan-session-revision", null,
  );
  const [target, setTarget] = useWorkspaceDraft(wb.caseId, "network", "scan-target", "127.0.0.1");
  const [notesWidth, setNotesWidth] = useState(320);
  const [ports, setPorts] = useWorkspaceDraft(wb.caseId, "network", "scan-ports", "top25");
  const [transport, setTransport] = useWorkspaceDraft<"tcp" | "udp">(
    wb.caseId, "network", "scan-transport", "tcp",
  );
  const [authorized, setAuthorized] = useState(false);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<ScanProgressWire | null>(null);
  const [results, setResults] = useState<ScanEntryWire[]>([]);
  const [discovered, setDiscovered] = useState<string[] | null>(null);
  const [arpInterfaces, setArpInterfaces] = useState<CaptureInterfaceV1[]>([]);
  const [arpInterface, setArpInterface] = useWorkspaceDraft(
    wb.caseId, "network", "scan-arp-interface", "",
  );
  const [arpBusy, setArpBusy] = useState(false);
  const [ndpBusy, setNdpBusy] = useState(false);
  const [icmpBusy, setIcmpBusy] = useState(false);
  const [icmpRows, setIcmpRows] = useState<IcmpObservationWire[] | null>(null);
  const [ndpNeighbors, setNdpNeighbors] = useState<ArpNeighborWire[] | null>(null);
  const [synBusy, setSynBusy] = useState(false);
  const [synProgress, setSynProgress] = useState<ScanProgressWire | null>(null);
  const [synFindings, setSynFindings] = useState<SynFindingWire[] | null>(null);
  const [arpNeighbors, setArpNeighbors] = useState<ArpNeighborWire[] | null>(null);
  const [observationPage, setObservationPage] = useState<ScanObservationPageWire | null>(null);
  const [observationOffset, setObservationOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<NetscanStatusWire>({ running: false, results: 0, saved_findings: 0, save_error: null });
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
    setArpNeighbors(null);
    setNdpNeighbors(null);
    setArpBusy(false);
    setNdpBusy(false);
    setIcmpBusy(false);
    setIcmpRows(null);
    setSynBusy(false);
    setSynFindings(null);
    setSynProgress(null);
    setObservationPage(null);
    setObservationOffset(0);
    setProgress(null);
    setError(null);
    setRunning(false);
  }, [identity]);

  useEffect(() => {
    if (!desktop) return;
    let active = true;
    void captureInterfacesV1().then((interfaces) => {
      if (active) setArpInterfaces(interfaces.filter(
        (iface) => iface.ethernet && iface.up && !iface.loopback,
      ));
    }).catch(() => { if (active) setArpInterfaces([]); });
    return () => { active = false; };
  }, [desktop]);

  const poll = useCallback(async () => {
    const caseId = wb.caseId;
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
  }, [identity, observationOffset]);

  useEffect(() => {
    if (!desktop) return;
    void poll();
    const timer = setInterval(() => void poll(), 900);
    return () => clearInterval(timer);
  }, [poll, desktop]);

  const start = async () => {
    if (running || status.running || revision === null) return;
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
    if (!desktop || revision === null || !authorized || running || status.running) return;
    const key = identity;
    setError(null);
    setDiscovered(null);
    try {
      const found = await netscanDiscoverHosts(target, authorized);
      if (activeCase.current === key) setDiscovered(found);
    } catch (err) {
      if (activeCase.current === key) setError(err instanceof Error ? err.message : String(err));
    }
  };

  const runSyn = async () => {
    if (!desktop || revision === null || !authorized || !arpInterface
      || synBusy || arpBusy || ndpBusy || icmpBusy || status.running || running) return;
    const key = identity;
    setError(null);
    setSynBusy(true);
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
  const stopSyn = async () => {
    try { await netscanSynStopV1(); }
    catch (err) { setError(err instanceof Error ? err.message : String(err)); }
  };

  const discoverArp = async () => {
    if (!desktop || revision === null || !authorized || !arpInterface
        || running || status.running || arpBusy || ndpBusy || synBusy || icmpBusy) return;
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
    if (!desktop || revision === null || !authorized || !arpInterface ||
      running || status.running || arpBusy || ndpBusy || synBusy || icmpBusy) return;
    const key = identity;
    setError(null);
    setIcmpRows(null);
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
  const stopIcmp = async () => {
    try { await netscanIcmpStopV1(); }
    catch (err) { setError(err instanceof Error ? err.message : String(err)); }
  };

  const discoverNdp = async () => {
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

  const openCount = observationPage?.open ?? results.filter((r) => r.state === "open").length;
  const observedCount = observationPage?.total ?? results.length;

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

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="cd-workspace-toolbar shrink-0 items-center gap-2  px-2">
        <span className="font-mono text-[10px] uppercase text-fg-muted">target</span>
        <TextInput value={target} onChange={setTarget} placeholder="IP, CIDR, !exclusion" ariaLabel="Scan target" className="w-56" />
        <Select
          value={transport}
          onChange={(value) => setTransport(value === "udp" ? "udp" : "tcp")}
          options={[{ value: "tcp", label: "TCP connect" }, { value: "udp", label: "UDP" }]}
          ariaLabel="Scan transport"
          className="w-32"
        />
        <span className="font-mono text-[10px] uppercase text-fg-muted">ports</span>
        <Select
          value={isPreset ? ports : "custom"}
          onChange={setPorts}
          options={[
            ...PORT_PRESETS,
            ...(isPreset ? [] : [{ value: ports, label: ports || "custom" }]),
          ]}
          ariaLabel="Port selection"
          className="w-44"
        />
        {!isPreset ? (
          <TextInput value={ports} onChange={setPorts} placeholder="80,443,8000-8100" ariaLabel="Custom ports" className="w-40" />
        ) : null}
        <ToolButton
          onClick={() => void discover()}
          disabled={!desktop || revision === null || !authorized || !target.trim() || running || status.running}
          title="Discover responding hosts using bounded case-authorized TCP probes"
        >
          Discover
        </ToolButton>
        {status.running || (running && scanCase.current === wb.caseId) ? (
          <ToolButton tone="danger" onClick={() => void stop()}>
            <Square size={11} /> Stop
          </ToolButton>
        ) : (
          <ToolButton
            tone="primary"
            onClick={() => void start()}
            disabled={!desktop || revision === null || !authorized || !target.trim() || status.running || running}
            title={revision === null ? "Select a saved native investigation case before scanning" : "Backend-selected case and native confirmation are required before network probes"}
          >
            <Play size={11} /> {running ? "scanning…" : "Run scan"}
          </ToolButton>
        )}
        <Chip tone={status.running || running ? "orange" : "muted"}>
          {running ? "running" : status.running ? "other session running" : "idle"}
        </Chip>
        {results.length > 0 ? (
          <>
            <ToolButton onClick={() => void exportResults("json")} title="Save results as JSON">JSON</ToolButton>
            <ToolButton onClick={() => void exportResults("csv")} title="Save results as CSV">CSV</ToolButton>
          </>
        ) : null}
        <span className="ml-auto font-mono text-[10px] text-fg-muted">{openCount} open / {observedCount} observed</span>
      </div>
      {error ? <div className="border-b border-err/50 bg-err/10 px-2 py-1 font-mono text-[10px] text-err">{error}</div> : null}
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
                  disabled={!desktop || !authorized || revision === null || !arpInterface
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
                  disabled={!desktop || !authorized || revision === null || !arpInterface ||
                    !target.trim() || running || status.running || arpBusy || synBusy}
                  title="Linux only: native case confirmation, selected NIC, fe80::/10 IPv6 target and CAP_NET_RAW required">
                  Discover NDP
                </ToolButton>
              )}
              <span className="font-mono text-[10px] text-fg-muted">
                NDP: 16 link-local IPv6 hosts · silence ≠ down
              </span>
              {icmpBusy ? (
                <ToolButton tone="danger" onClick={() => void stopIcmp()}>
                  <Square size={11} /> Stop ICMP
                </ToolButton>
              ) : (
                <ToolButton onClick={() => void discoverIcmp()}
                  disabled={!desktop || !authorized || revision === null || !arpInterface ||
                    !target.trim() || running || status.running || arpBusy || ndpBusy || synBusy}
                  title="Linux only: explicitly confirmed native ICMPv4 echo requests with CAP_NET_RAW">
                  ICMP Echo
                </ToolButton>
              )}
              <span className="font-mono text-[10px] text-fg-muted">
                ICMPv4: up to 32 hosts
              </span>
              {synBusy ? (
                <ToolButton tone="danger" onClick={() => void stopSyn()} title="Stop case-authorized raw SYN scan">
                  <Square size={11} /> Stop SYN
                </ToolButton>
              ) : (
                <ToolButton onClick={() => void runSyn()}
                  disabled={!desktop || !authorized || revision === null || !arpInterface
                    || !target.trim() || !ports.trim() || running || status.running || arpBusy}
                  title="Linux only: CAP_NET_RAW, selected interface, backend saved-case authorization and native confirmation required">
                  <Play size={11} /> Raw SYN
                </ToolButton>
              )}
              {synProgress ? (
                <span className="font-mono text-[10px] text-fg-muted">
                  SYN {synProgress.tried}/{synProgress.total} · {synProgress.percent}%
                </span>
              ) : null}
            </div>
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
                title={running ? "Scanning…" : "No results"}
                detail="Case-authorized TCP connect or connected-UDP scan. UDP silence remains inconclusive, not filtered. Confirm scope in the native dialog."
                badge="netscan"
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
            native TCP connect and connected UDP observations; IPv4/IPv6 CIDR and
            comma-separated exclusions (!address or !CIDR). DNS/NTP UDP replies must match
            our queries; UDP timeouts stay inconclusive. Full SYN/UDP-ICMP parity is not
            yet available. Nmap source and fingerprints are not bundled.
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
                Correlated TCP SYN: {synFindings.length} observations · {synFindings.filter((r) => r.state === "open").length} open
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
          {icmpRows !== null ? (
            <div className="border-t border-line p-2 text-[10px] text-fg-muted">
              <div className="mb-1 font-semibold text-fg">
                IPv4 ICMP echo: {icmpRows.filter((r) => r.state === "responded").length} responding / {icmpRows.length} checked
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

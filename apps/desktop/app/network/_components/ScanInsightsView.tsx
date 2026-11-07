"use client";
/**
 * Scan Insights: ndiff-grade comparison and topology projection of completed
 * native scan sessions. Purely read-only: every data path is a typed Tauri
 * command over the same scanner storage the Scanning tool uses; nothing here
 * starts a probe. Calling topology also pins the backend's bounded per-session
 * snapshot (the capture step that keeps cross-session diffs possible).
 *
 * UX revision (Zenmap reference): an icon rail picks ONE focused mode at a
 * time — Diff or Topology — and each mode gets a single dense toolbar row.
 * Every long explanation (honesty contract, topology legend, case-gate
 * rationale) lives in an InfoTip tooltip instead of on-screen prose, so the
 * screen shows controls and results, not text walls.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { GitCompare, Network, Play } from "lucide-react";
import { Chip, Select } from "@ds/panes";
import { EmptyCard, ErrorStrip, IconRail, IconButton, InfoTip, StatusStrip, WorkspaceShell } from "@ds/compact";
import {
  isDesktop, netscanHistory, netscanDiffV1, netscanTopologyV1,
  type ScanHistoryItemWire, type ScanDiffWire, type ScanTopologyWire,
} from "@lib/ipc";
import { useCaseReady } from "@state/workbench";
import { CaseGate } from "@ds/case-gate";
import {
  hostChangeCount,
  formatSessionLabel,
  formatStateChange,
  radialLayout,
  TOPOLOGY_NODE_LIMIT,
  topologyNodeRadius,
} from "./scan-insights-ipc";

/** Poll cadence for the read-only session history sweep. */
const HISTORY_POLL_MS = 1500;
/** SVG canvas the deterministic radial layout positions nodes on. */
const TOPOLOGY_WIDTH = 1000;
const TOPOLOGY_HEIGHT = 620;

/** Honesty contract for both projections; tooltip text, never body copy. */
const HONESTY_NOTE = `Host "up" means at least one open port: connect scans observe no host-status header, so silence is never presence. Sessions pair on the IP string, ports on port/proto (ndiff semantics). Insights retain the last 8 completed scans of the selected case in memory; a case switch, re-selection or app restart clears them. No ARP or MAC records are retained, so host-to-host links stay inferred subnet grouping and only this deck's own segment claims l2 adjacency.`;

/** Topology legend (was a prose footer) + the honesty contract, one hover away. */
const TOPOLOGY_NOTE = "node size = open ports · solid = l2 on-link (this deck's own segment)"
  + " · dashed = subnet /24 or /64 (inferred) · green ring = this deck. " + HONESTY_NOTE;

/** The two focused modes; the rail keeps exactly one on screen. */
type InsightsMode = "diff" | "topology";

const MODE_RAIL_ITEMS = [
  { id: "diff", label: "Diff", icon: GitCompare },
  { id: "topology", label: "Topology", icon: Network },
];

export function ScanInsightsView() {
  const desktop = isDesktop();
  const { caseId, caseRevision, caseReady } = useCaseReady();
  const revision = caseReady ? caseRevision : null;
  const identity = caseId + ":" + String(revision);

  const [mode, setMode] = useState<InsightsMode>("diff");
  const [history, setHistory] = useState<ScanHistoryItemWire[]>([]);
  const [baselineId, setBaselineId] = useState("");
  const [compareId, setCompareId] = useState("");
  const [topologyId, setTopologyId] = useState("");
  const [diff, setDiff] = useState<ScanDiffWire | null>(null);
  const [diffBusy, setDiffBusy] = useState(false);
  const [topology, setTopology] = useState<ScanTopologyWire | null>(null);
  const [topoBusy, setTopoBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const activeCase = useRef(identity);
  activeCase.current = identity;
  const pollTicket = useRef(0);
  // Session ids already pinned by a read-only topology capture (attempted or
  // done). A failed capture is not retried: the backend re-syncs the most
  // recent session on every insights command anyway.
  const capturedIds = useRef<Set<number>>(new Set());
  const topologyIdRef = useRef("");
  topologyIdRef.current = topologyId;

  // Case switch or revision bump invalidates every retained read.
  useEffect(() => {
    pollTicket.current += 1;
    setHistory([]);
    setBaselineId("");
    setCompareId("");
    setTopologyId("");
    setDiff(null);
    setTopology(null);
    setDiffBusy(false);
    setTopoBusy(false);
    setError(null);
    capturedIds.current = new Set();
  }, [identity]);

  const sweepHistory = useCallback(async () => {
    if (revision === null || !desktop) return;
    const key = identity;
    const ticket = ++pollTicket.current;
    const isCurrent = () => activeCase.current === key && ticket === pollTicket.current;
    try {
      const items = await netscanHistory();
      if (!isCurrent()) return;
      setHistory(items);
      // Read-only capture of the newest not-yet-pinned completed session. One
      // per sweep keeps the poll cheap; the command itself is bounded.
      const newest = items[items.length - 1];
      if (newest && !capturedIds.current.has(newest.id)) {
        capturedIds.current.add(newest.id);
        const pin = String(newest.id);
        void netscanTopologyV1(newest.id)
          .then((wire) => {
            if (isCurrent() && topologyIdRef.current === pin) setTopology(wire);
          })
          .catch(() => {
            if (isCurrent() && topologyIdRef.current === pin) setTopology(null);
          });
      }
    } catch {
      // History reads return empty outside the selected case; silence keeps
      // the picker calm during case switches.
      if (isCurrent()) setHistory([]);
    }
  }, [desktop, identity, revision]);

  useEffect(() => {
    if (!desktop || revision === null) return;
    void sweepHistory();
    const timer = setInterval(() => void sweepHistory(), HISTORY_POLL_MS);
    return () => clearInterval(timer);
  }, [desktop, revision, sweepHistory]);

  // Render topology whenever a session is selected (picker or auto-default).
  useEffect(() => {
    if (!desktop || revision === null || !topologyId) return;
    let cancelled = false;
    const key = identity;
    setTopoBusy(true);
    void netscanTopologyV1(Number(topologyId))
      .then((wire) => {
        if (!cancelled && activeCase.current === key) setTopology(wire);
      })
      .catch((cause) => {
        if (!cancelled && activeCase.current === key) {
          setTopology(null);
          setError("Topology unavailable: " + String(cause));
        }
      })
      .finally(() => {
        if (!cancelled && activeCase.current === key) setTopoBusy(false);
      });
    return () => { cancelled = true; };
  }, [desktop, revision, topologyId, identity]);

  const options = useMemo(
    () => history.map((item) => ({ value: String(item.id), label: formatSessionLabel(item) })),
    [history],
  );

  // Defaults once history arrives: compare the two most recent sessions.
  useEffect(() => {
    if (history.length === 0) return;
    const newest = String(history[history.length - 1].id);
    const previous = history.length > 1 ? String(history[history.length - 2].id) : newest;
    setCompareId((current) => current || newest);
    setBaselineId((current) => current || previous);
    setTopologyId((current) => current || newest);
  }, [history]);

  const runDiff = async () => {
    if (!desktop || revision === null || diffBusy || !baselineId || !compareId) return;
    if (baselineId === compareId) return;
    const key = identity;
    setDiffBusy(true);
    setError(null);
    try {
      const wire = await netscanDiffV1(Number(baselineId), Number(compareId));
      if (activeCase.current === key) setDiff(wire);
    } catch (cause) {
      if (activeCase.current === key) {
        setDiff(null);
        setError(String(cause));
      }
    } finally {
      if (activeCase.current === key) setDiffBusy(false);
    }
  };

  const layout = useMemo(() => {
    if (!topology) return [];
    // Belt-and-braces bound on the client too; the backend already caps.
    return radialLayout(topology.nodes.slice(0, TOPOLOGY_NODE_LIMIT), TOPOLOGY_WIDTH, TOPOLOGY_HEIGHT);
  }, [topology]);
  const positions = useMemo(() => new Map(layout.map((node) => [node.id, node])), [layout]);

  const totalChanged = diff ? diff.changed_hosts.reduce((sum, host) => sum + hostChangeCount(host), 0) : 0;

  // One muted strip of state per mode: result counts plus the single action
  // hint (fewer than two sessions). No loose explanatory text anywhere.
  const statusItems: readonly ({ label: string; tone?: "muted" | "orange" | "ok" | "err" } | null)[] = mode === "diff"
    ? [
      diff
        ? { label: `${diff.new_hosts.length} new · ${diff.lost_hosts.length} lost`
          + ` · ${diff.changed_hosts.length} changed · ${totalChanged} port changes` }
        : null,
      diff
        ? { label: `baseline #${diff.session_a_id}: ${diff.summary.hosts_up_a} up / ${diff.summary.ports_open_a} open`
          + ` · compare #${diff.session_b_id}: ${diff.summary.hosts_up_b} up / ${diff.summary.ports_open_b} open` }
        : null,
      history.length < 2 ? { label: "select two completed sessions to diff" } : null,
    ]
    : [
      topology ? { label: `${topology.nodes.length} nodes · ${topology.edges.length} edges` } : null,
    ];
  return (
    <WorkspaceShell
      rail={
        <IconRail
          items={MODE_RAIL_ITEMS}
          active={mode}
          onChange={(id) => setMode(id as InsightsMode)}
          ariaLabel="Insights mode"
        />
      }
      toolbar={mode === "diff" ? (
        <>
          <Select
            value={baselineId}
            onChange={setBaselineId}
            options={options.length > 0 ? options : [{ value: "", label: "baseline" }]}
            ariaLabel="Baseline scan session"
            className="w-56"
          />
          <span className="font-mono text-3xs text-fg-muted">→</span>
          <Select
            value={compareId}
            onChange={setCompareId}
            options={options.length > 0 ? options : [{ value: "", label: "compare" }]}
            ariaLabel="Compare scan session"
            className="w-56"
          />
          <IconButton
            icon={Play}
            onClick={() => void runDiff()}
            disabled={!desktop || revision === null || diffBusy || !baselineId || !compareId || baselineId === compareId}
            title="Run diff — ndiff-style comparison: hosts pair on IP, ports on port/proto; both sessions must still be retained"
          />
          {diffBusy ? <Chip tone="orange">diffing</Chip> : null}
          <Chip tone="muted">{`${history.length} sessions`}</Chip>
          <span className="ml-auto"><InfoTip text={HONESTY_NOTE} /></span>
        </>
      ) : (
        <>
          <Select
            value={topologyId}
            onChange={setTopologyId}
            options={options.length > 0 ? options : [{ value: "", label: "session" }]}
            ariaLabel="Topology scan session"
            className="w-56"
          />
          {topoBusy ? <Chip tone="orange">rendering</Chip> : null}
          <Chip tone="muted">{`${history.length} sessions`}</Chip>
          <span className="ml-auto"><InfoTip text={TOPOLOGY_NOTE} /></span>
        </>
      )}
      status={statusItems.some((item) => item !== null) ? <StatusStrip items={statusItems} /> : undefined}
      contentClassName="flex flex-col"
    >
      {error ? <ErrorStrip>{error}</ErrorStrip> : null}
      <CaseGate activity="Scan insights" />
      <div className="flex min-h-0 flex-1 flex-col bg-panel">
        {!desktop ? (
          <EmptyCard icon={GitCompare} title="Scan insights require the desktop runtime">
            The desktop runtime collects the scan sessions these views compare.
          </EmptyCard>
        ) : mode === "diff" ? (
          !diff ? (
            <EmptyCard icon={GitCompare}
              title={history.length === 0 ? "No completed scan sessions yet" : "Pick a baseline and a compare session"}>
              ndiff semantics: pair two completed sessions; ports compare per port/proto.
            </EmptyCard>
          ) : (
            <div className="min-h-0 flex-1 overflow-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th className="w-56">Host</th>
                    <th className="w-44">Ports added</th>
                    <th className="w-44">Ports removed</th>
                    <th>State changes</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="bg-raised">
                    <td colSpan={4} className="font-semibold uppercase tracking-wider text-fg-muted">
                      Changed hosts ({diff.changed_hosts.length})
                    </td>
                  </tr>
                  {diff.changed_hosts.map((host) => (
                    <tr key={host.host}>
                      <td className="text-fg" title={hostChangeCount(host) + " recorded port-level changes"}>
                        {host.host}
                      </td>
                      <td className="text-ok">
                        {host.ports_added.length > 0
                          ? host.ports_added.map((port) => <div key={port}>+ {port}</div>)
                          : <span className="text-fg-muted">—</span>}
                      </td>
                      <td className="text-err">
                        {host.ports_removed.length > 0
                          ? host.ports_removed.map((port) => <div key={port}>− {port}</div>)
                          : <span className="text-fg-muted">—</span>}
                      </td>
                      <td className="text-fg">
                        {host.state_changes.length > 0
                          ? host.state_changes.map((change) => (
                            <div key={change.port} className="text-fg-muted">{formatStateChange(change)}</div>
                          ))
                          : <span className="text-fg-muted">—</span>}
                      </td>
                    </tr>
                  ))}
                  <tr className="bg-raised">
                    <td colSpan={4} className="font-semibold uppercase tracking-wider text-fg-muted">
                      New hosts ({diff.new_hosts.length}) · up in compare, no open port in baseline
                    </td>
                  </tr>
                  {diff.new_hosts.map((host) => (
                    <tr key={"new-" + host}>
                      <td className="text-ok">+ {host}</td>
                      <td colSpan={3} className="text-fg-muted">first seen up in session #{diff.session_b_id}</td>
                    </tr>
                  ))}
                  {diff.new_hosts.length === 0 ? (
                    <tr><td colSpan={4} className="text-fg-muted">none</td></tr>
                  ) : null}
                  <tr className="bg-raised">
                    <td colSpan={4} className="font-semibold uppercase tracking-wider text-fg-muted">
                      Lost hosts ({diff.lost_hosts.length}) · up in baseline, no open port in compare
                    </td>
                  </tr>
                  {diff.lost_hosts.map((host) => (
                    <tr key={"lost-" + host}>
                      <td className="text-err">− {host}</td>
                      <td colSpan={3} className="text-fg-muted">no open-port evidence in session #{diff.session_b_id}; silence is not proof a host is down</td>
                    </tr>
                  ))}
                  {diff.lost_hosts.length === 0 ? (
                    <tr><td colSpan={4} className="text-fg-muted">none</td></tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          )
        ) : !topology ? (
          <EmptyCard icon={Network}
            title={topoBusy ? "Rendering topology…" : "No topology rendered"}>
            Topology renders from a completed scan session's observed hosts.
          </EmptyCard>
        ) : (
          <div className="flex h-full min-h-0 flex-col">
            {topology.truncated ? (
              <div className="shrink-0 border-b border-warn/40 bg-warn/10 px-2 py-1 font-mono text-3xs text-warn" role="status">
                more hosts observed than the {TOPOLOGY_NODE_LIMIT}-node bound; showing the lowest addresses deterministically
              </div>
            ) : null}
            <svg
              viewBox={`0 0 ${TOPOLOGY_WIDTH} ${TOPOLOGY_HEIGHT}`}
              preserveAspectRatio="xMidYMid meet"
              className="h-full w-full flex-1"
              role="img"
              aria-label={"Network topology of scan session " + topology.session_id}
            >
              {topology.edges.map((edge) => {
                const a = positions.get(edge.a);
                const b = positions.get(edge.b);
                if (!a || !b) return null;
                return (
                  <line
                    key={edge.kind + "-" + edge.a + "-" + edge.b}
                    x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                    stroke={edge.kind === "l2" ? "var(--color-ok)" : "var(--color-fg-muted)"}
                    strokeWidth={edge.kind === "l2" ? 1.6 : 1}
                    strokeDasharray={edge.kind === "l2" ? undefined : "5 4"}
                  >
                    <title>{edge.kind === "l2"
                      ? `l2 on-link adjacency: ${edge.a} ↔ ${edge.b} (this deck's own segment)`
                      : `subnet grouping: ${edge.a} ↔ ${edge.b} (same /24 or /64, inferred)`}</title>
                  </line>
                );
              })}
              {layout.map((node) => {
                const radius = topologyNodeRadius(node.open_port_count);
                return (
                  <g key={node.id} transform={`translate(${node.x} ${node.y})`} className="cursor-default">
                    <circle
                      r={radius}
                      fill="var(--color-app)"
                      stroke={node.is_local ? "var(--color-ok)" : "var(--color-fg-muted)"}
                      strokeWidth={node.is_local ? 2.5 : 1.2}
                    />
                    <text
                      y={radius + 11}
                      textAnchor="middle"
                      className="font-mono"
                      fontSize="10"
                      fill="var(--color-fg-muted)"
                    >
                      {node.label}
                    </text>
                    <title>
                      {node.label} · {node.open_port_count} open port{node.open_port_count === 1 ? "" : "s"}
                      {node.is_local ? " · this deck" : ""}
                    </title>
                  </g>
                );
              })}
            </svg>
          </div>
        )}
      </div>
    </WorkspaceShell>
  );
}

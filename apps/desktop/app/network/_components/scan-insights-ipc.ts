/**
 * Scan Insights pending IPC client + pure view helpers.
 *
 * The canonical clients and wire types will be folded into lib/ipc.ts by the
 * coordinator; until then this module follows the network-lab-model.ts
 * pattern: typed wrappers calling `invoke` directly (never raw paths, never
 * process spawning), wire field names exactly mirroring the Rust serde
 * structs in src-tauri/src/features/network/ipc/scan_insights.rs, and pure
 * helpers at the bottom that node --test exercises directly.
 */
import { invoke } from "@tauri-apps/api/core";

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// --- wire types (mirror scan_insights.rs serde structs) ----------------------

export interface ScanDiffStateChangeWire {
  port: string;
  from: string;
  to: string;
}

export interface ScanDiffHostWire {
  host: string;
  ports_added: string[];
  ports_removed: string[];
  state_changes: ScanDiffStateChangeWire[];
}

export interface ScanDiffSummaryWire {
  hosts_up_a: number;
  hosts_up_b: number;
  ports_open_a: number;
  ports_open_b: number;
}

export interface ScanDiffWire {
  session_a_id: number;
  session_b_id: number;
  new_hosts: string[];
  lost_hosts: string[];
  changed_hosts: ScanDiffHostWire[];
  summary: ScanDiffSummaryWire;
}

export interface TopologyNodeWire {
  id: string;
  label: string;
  open_port_count: number;
  is_local: boolean;
}

export interface TopologyEdgeWire {
  a: string;
  b: string;
  kind: "l2" | "subnet";
}

export interface ScanTopologyWire {
  session_id: number;
  nodes: TopologyNodeWire[];
  edges: TopologyEdgeWire[];
  truncated: boolean;
}

// --- pending canonical clients ----------------------------------------------

/** ndiff-style comparison of two completed scan sessions of the selected case. */
export async function netscanDiffV1(
  sessionAId: number,
  sessionBId: number,
): Promise<ScanDiffWire> {
  if (!inTauri) throw new Error("scan insights require the desktop runtime");
  if (!Number.isSafeInteger(sessionAId) || sessionAId <= 0
    || !Number.isSafeInteger(sessionBId) || sessionBId <= 0) {
    throw new Error("invalid bounded scan session ids");
  }
  return invoke<ScanDiffWire>("netscan_diff_v1", { sessionAId, sessionBId });
}

/**
 * Topology projection of one completed scan session. Calling this also pins
 * that session into the backend's bounded snapshot store (read-only capture),
 * which is what keeps cross-session diffs possible after newer scans run.
 */
export async function netscanTopologyV1(sessionId: number): Promise<ScanTopologyWire> {
  if (!inTauri) throw new Error("scan insights require the desktop runtime");
  if (!Number.isSafeInteger(sessionId) || sessionId <= 0) {
    throw new Error("invalid bounded scan session id");
  }
  return invoke<ScanTopologyWire>("netscan_topology_v1", { sessionId });
}

// --- pure helpers (node --test exercises these directly) ----------------------

/** Mirrors the backend's topology node bound (scan_insights.rs). */
export const TOPOLOGY_NODE_LIMIT = 512;

/** Minimal structural shape of ScanHistoryItemWire (lib/ipc.ts). */
export interface SessionHistoryItem {
  id: number;
  targets: string;
  open_ports: number;
  at_ms: number;
}

/** Stable picker label; malformed timestamps render as "unknown time". */
export function formatSessionLabel(item: SessionHistoryItem): string {
  const date = new Date(item.at_ms);
  const stamp = Number.isFinite(date.getTime())
    ? date.toISOString().replace("T", " ").slice(0, 19) + " UTC"
    : "unknown time";
  return `#${item.id} · ${stamp} · ${item.targets} · ${item.open_ports} open`;
}

export interface LayoutNode {
  id: string;
  label: string;
  open_port_count: number;
  is_local: boolean;
  x: number;
  y: number;
}

/**
 * Deterministic radial layout for the topology SVG. The local node(s) sit at
 * the center; every other node sits on concentric rings ordered by descending
 * open-port count then id, with a per-ring angular offset so consecutive
 * rings never line up into spokes. Ring radii are distributed between an
 * inner and an outer radius computed from the canvas so even a full 512-node
 * graph stays inside the viewBox. Same input always yields the same
 * positions: no physics simulation, no randomness.
 */
export function radialLayout(
  nodes: TopologyNodeWire[],
  width: number,
  height: number,
): LayoutNode[] {
  const centerX = width / 2;
  const centerY = height / 2;
  if (nodes.length === 0) return [];
  const ordered = [...nodes].sort((a, b) => {
    if (a.is_local !== b.is_local) return a.is_local ? -1 : 1;
    if (a.open_port_count !== b.open_port_count) return b.open_port_count - a.open_port_count;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
  const locals = ordered.filter((node) => node.is_local);
  const others = ordered.filter((node) => !node.is_local);
  const positions = new Map<string, { x: number; y: number }>();
  if (locals.length > 0) {
    // One local node takes the exact center; extra local nodes join the
    // rings rather than stacking invisibly on top of each other.
    positions.set(locals[0].id, { x: centerX, y: centerY });
    others.push(...locals.slice(1));
  }
  const innerRadius = Math.min(width, height) * 0.16;
  // Keeping the outer radius inside half of the smaller canvas dimension
  // guarantees every ring stays in the viewBox on both axes.
  const outerRadius = Math.max(Math.min(width, height) / 2 - 24, innerRadius + 1);
  const ringCapacity = (ring: number) => 10 + ring * 6;
  // Smallest ring count whose cumulative capacity holds every outside node.
  let maxRing = 0;
  for (let capacity = 0; capacity < others.length; maxRing += 1) {
    capacity += ringCapacity(maxRing);
  }
  let ring = 0;
  let indexInRing = 0;
  for (const node of others) {
    if (indexInRing >= ringCapacity(ring)) {
      ring += 1;
      indexInRing = 0;
    }
    const fraction = maxRing <= 1 ? 0 : ring / (maxRing - 1);
    const radius = others.length === 1
      ? innerRadius
      : innerRadius + (outerRadius - innerRadius) * fraction;
    const angle = (indexInRing / ringCapacity(ring)) * Math.PI * 2 + ring * 0.55;
    positions.set(node.id, {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
    });
    indexInRing += 1;
  }
  return ordered.map((node) => {
    const spot = positions.get(node.id) ?? { x: centerX, y: centerY };
    return {
      id: node.id,
      label: node.label,
      open_port_count: node.open_port_count,
      is_local: node.is_local,
      x: spot.x,
      y: spot.y,
    };
  });
}

/** Node radius grows with affirmative open-port evidence, bounded for layout. */
export function topologyNodeRadius(openPortCount: number): number {
  return 5 + Math.min(Math.max(openPortCount, 0), 24) * 1.1;
}

/** Total port-level changes of one changed host, in wire order. */
export function hostChangeCount(host: ScanDiffHostWire): number {
  return host.ports_added.length + host.ports_removed.length + host.state_changes.length;
}

/** "80/tcp: open → closed" one-line rendering of a state change. */
export function formatStateChange(change: ScanDiffStateChangeWire): string {
  return `${change.port}: ${change.from} → ${change.to}`;
}

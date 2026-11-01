/**
 * Web feature controller: pure helpers shared by the web views.
 */
import { useState } from "react";
import type { CapturedRequestWire } from "@lib/ipc";

/** Shared target input with http:// normalization. */
export function useTarget() {
  const [target, setTarget] = useState("");
  const normalized = target.trim().length > 0 && !target.trim().startsWith("http") ? `http://${target.trim()}` : target.trim();
  return { target, setTarget, normalized };
}

/** Filter captured requests by free-text query across method/host/path/status. */
export function filterCaptured(rows: CapturedRequestWire[], query: string): CapturedRequestWire[] {
  const q = query.trim().toLowerCase();
  if (!q) return rows;
  return rows.filter(
    (r) =>
      r.method.toLowerCase().includes(q) ||
      r.host.toLowerCase().includes(q) ||
      r.path.toLowerCase().includes(q) ||
      String(r.status) === q,
  );
}

/** Build the host -> paths tree from captured traffic. */
export function buildSitesTree(rows: CapturedRequestWire[]): Map<string, Set<string>> {
  const hosts = new Map<string, Set<string>>();
  for (const r of rows) {
    if (!hosts.has(r.host)) hosts.set(r.host, new Set());
    hosts.get(r.host)!.add(r.path.split("?")[0]);
  }
  return hosts;
}

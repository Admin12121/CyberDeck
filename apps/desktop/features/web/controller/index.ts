/**
 * Web feature controller layer.
 * Pure filter/selection transitions. Proxy control (listener state,
 * interception, certificate lifecycle) arrives arc 4 through lib/ipc.
 */
import type { HistoryRow } from "../model";

export function filterHistory(rows: HistoryRow[], query: string): HistoryRow[] {
  const q = query.trim().toLowerCase();
  if (!q) return rows;
  return rows.filter(
    (r) =>
      r.method.toLowerCase() === q ||
      r.host.toLowerCase().includes(q) ||
      r.path.toLowerCase().includes(q) ||
      String(r.status) === q,
  );
}

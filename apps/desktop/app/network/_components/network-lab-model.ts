/**
 * Network Lab model layer (passive/defensive arc).
 *
 * Wire types and IPC wrappers are re-exported from the canonical lib/ipc.ts
 * Network Lab block, which mirrors the Rust serde structs in
 * src-tauri/src/features/network/ipc/network_lab.rs and
 * crates/packet/src/arp_watch.rs exactly; field names are the serialized
 * snake_case names, never renamed on the way to the UI.
 *
 * Pure helpers (parsing, labels, summaries) sit at the bottom and are the
 * only things node --test exercises directly.
 */
import type {
  NetworkLabFindingKindWire,
  NetworkLabMacClaimWire,
  NetworkLabScopeWire,
} from "../../../lib/ipc.ts";

export {
  networkLabAnalyzePcapV1,
  networkLabSetScopeV1,
  networkLabScopeV1,
  type NetworkLabAnalysisWire,
  type NetworkLabFindingWire,
  type NetworkLabHostWire,
  type NetworkLabMacClaimWire,
  type NetworkLabScopeWire,
} from "../../../lib/ipc.ts";

// --- pure helpers (node-testable) --------------------------------------------

/** Mirrors the backend's per-group scope cap (network_lab.rs). */
export const LAB_SCOPE_MAX_ENTRIES = 64;

/**
 * Split a Target textarea blob into entries: commas and newlines both
 * separate, whitespace around entries is dropped, empties never reach the
 * backend (it rejects them with an error that would only confuse the user).
 */
export function parseScopeEntries(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/**
 * Absolute-epoch-ms label for first/last seen. Zero or non-finite renders as
 * an em dash: the capture may simply lack wall-clock provenance, and a fake
 * 1970 timestamp would be dishonest.
 */
export function formatSeenMs(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "—";
  const date = new Date(ms);
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function findingKindLabel(kind: NetworkLabFindingKindWire): string {
  switch (kind) {
    case "ip_impersonation":
      return "IP impersonation";
    case "gateway_impersonation":
      return "Gateway impersonation";
    case "gratuitous_burst":
      return "Gratuitous ARP burst";
  }
}

/** "aa:bb:.. (3), cc:dd:.. (1)" — incumbent MAC first (backend pre-sorts). */
export function summarizeMacClaims(claims: NetworkLabMacClaimWire[]): string {
  return claims.map((claim) => `${claim.mac} (${claim.claims})`).join(", ");
}

/** Total claim count across MACs for a finding row's Claims column. */
export function totalClaims(claims: NetworkLabMacClaimWire[]): number {
  return claims.reduce((sum, claim) => sum + claim.claims, 0);
}

/** Scope status chip text: entry counts plus authorization state. */
export function scopeSummary(scope: NetworkLabScopeWire | null): string {
  if (!scope) return "scope: unknown";
  if (!scope.authorized) return "scope: not set";
  return `scope: T1 ${scope.targets_t1.length} · T2 ${scope.targets_t2.length} · authorized`;
}

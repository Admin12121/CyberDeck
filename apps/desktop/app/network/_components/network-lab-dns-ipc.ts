/**
 * Local IPC client for the Bettercap-mode passive DNS-response monitor.
 *
 * The lab watches DNS queries/answers in the OPENED capture and raises
 * interception indicators (answer inconsistency, loopback/link-local answer
 * targets, NXDOMAIN injection) — the dns-spoofing detection counterpart,
 * strictly passive: it never transmits, resolves or injects anything.
 *
 * This module is deliberately separate from lib/ipc.ts so the canonical
 * client block can be merged there later without a cross-feature edit; the
 * wire types mirror crates/packet/src/dns_monitor.rs and
 * features/network/ipc/network_lab.rs DnsMonitorWire exactly (snake_case
 * serialized names, never renamed).
 */
import { invoke } from "@tauri-apps/api/core";

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export type DnsFindingKindWire =
  | "answer_inconsistency"
  | "suspicious_target"
  | "nxdomain_injection";

/** One answer-set snapshot: normalized A/AAAA values plus when observed. */
export interface DnsAnswerSetWire {
  values: string[];
  seen_ms: number;
}

export interface DnsFindingWire {
  kind: DnsFindingKindWire;
  question_name: string;
  question_type: number;
  /** First-observed answer set — inconsistency findings only. */
  baseline: DnsAnswerSetWire | null;
  /** The later, differing answer set — inconsistency findings only. */
  later: DnsAnswerSetWire | null;
  first_seen_ms: number;
  last_seen_ms: number;
  detail: string;
}

export interface DnsMonitorWire {
  /** DNS messages reduced into monitor observations (queries + responses). */
  observations_seen: number;
  /** Bounded interception indicators (backend caps at 128). */
  findings: DnsFindingWire[];
  /** Distinct question names seen (backend caps tracking at 512). */
  queried_names: number;
}

/**
 * Read-only passive DNS monitoring over the currently opened capture. The
 * backend walks the cached packets and never touches the network.
 */
export async function networkLabDnsMonitorV1(): Promise<DnsMonitorWire> {
  if (!inTauri) throw new Error("DNS monitoring requires the desktop runtime");
  return invoke<DnsMonitorWire>("network_lab_dns_monitor_v1");
}

// --- pure helpers (node-testable) ---------------------------------------------

/** One-line label per finding kind; mirrors DnsFindingKind in dns_monitor.rs. */
export function dnsFindingKindLabel(kind: DnsFindingKindWire): string {
  switch (kind) {
    case "answer_inconsistency":
      return "Answer inconsistency";
    case "suspicious_target":
      return "Suspicious target";
    case "nxdomain_injection":
      return "NXDOMAIN injection";
  }
}

/** Question-type label mirroring dns.rs record_type_label for common types. */
export function questionTypeLabel(questionType: number): string {
  switch (questionType) {
    case 1:
      return "A";
    case 2:
      return "NS";
    case 5:
      return "CNAME";
    case 6:
      return "SOA";
    case 12:
      return "PTR";
    case 15:
      return "MX";
    case 16:
      return "TXT";
    case 28:
      return "AAAA";
    case 33:
      return "SRV";
    case 255:
      return "ANY";
    default:
      return `TYPE${questionType}`;
  }
}

/**
 * Answer-set cell text: the normalized A/AAAA values, or an em dash when the
 * finding kind carries no answer set (a fabricated "none" would be dishonest).
 */
export function formatAnswerSet(set: DnsAnswerSetWire | null): string {
  if (!set || set.values.length === 0) return "—";
  return set.values.join(", ");
}

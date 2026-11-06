/**
 * Network Lab DNS monitor: wire types and the invoke client live in the
 * canonical lib/ipc.ts block (mirroring crates/packet/src/dns_monitor.rs and
 * features/network/ipc/network_lab.rs serde names exactly). This module
 * keeps only the pure presentation helpers node --test exercises directly;
 * the relative .ts import keeps node's TS-strip loader able to resolve it.
 */
import type {
  DnsAnswerSetWire,
  DnsFindingKindWire,
} from "../../../lib/ipc.ts";

export {
  networkLabDnsMonitorV1,
  type DnsAnswerSetWire,
  type DnsFindingKindWire,
  type DnsFindingWire,
  type DnsMonitorWire,
} from "../../../lib/ipc.ts";

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
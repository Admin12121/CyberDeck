/**
 * Display-filter language for Packet Studio (Master Plan §5.1 "validate
 * syntax visibly"). A small recursive-descent parser over the same shape the
 * Rust dissector emits: rows carry source/destination/protocol/length/info
 * plus label/value layers. The language is intentionally narrower than
 * Wireshark's: every accepted field maps onto data this engine actually has.
 *
 * Grammar:
 *   orExpr   := andExpr ("or" andExpr)*
 *   andExpr  := notExpr ("and" notExpr)*
 *   notExpr  := "not" notExpr | primary
 *   primary  := "(" orExpr ")" | comparison | protocolName
 *   comparison := field op value        op := == != > >= < <= contains
 */

import type { FilterPacket } from "./index";

export interface FilterPositionedError {
  message: string;
  /** 0-based byte offset into the original filter text. */
  position: number;
}

type Token =
  | { kind: "word"; text: string; start: number }
  | { kind: "number"; value: number; start: number }
  | { kind: "string"; value: string; start: number }
  | { kind: "op"; text: "==" | "!=" | ">" | ">=" | "<" | "<="; start: number }
  | { kind: "lparen"; start: number }
  | { kind: "rparen"; start: number };

const OPERATOR_TEXTS = ["==", "!=", ">=", "<=", ">", "<"] as const;

function tokenize(filter: string): { tokens: Token[] } | { error: FilterPositionedError } {
  const tokens: Token[] = [];
  let i = 0;
  while (i < filter.length) {
    const ch = filter[i];
    if (/\s/.test(ch)) {
      i += 1;
      continue;
    }
    if (ch === "(") {
      tokens.push({ kind: "lparen", start: i });
      i += 1;
      continue;
    }
    if (ch === ")") {
      tokens.push({ kind: "rparen", start: i });
      i += 1;
      continue;
    }
    const two = filter.slice(i, i + 2);
    if ((OPERATOR_TEXTS as readonly string[]).includes(two)) {
      tokens.push({ kind: "op", text: two as "==" | "!=" | ">" | ">=" | "<" | "<=", start: i });
      i += 2;
      continue;
    }
    if ((OPERATOR_TEXTS as readonly string[]).includes(ch)) {
      tokens.push({ kind: "op", text: ch as "==" | "!=" | ">" | ">=" | "<" | "<=", start: i });
      i += 1;
      continue;
    }
    if (ch === '"' || ch === "'") {
      const end = filter.indexOf(ch, i + 1);
      if (end === -1) {
        return { error: { message: `unterminated string starting at position ${i + 1}`, position: i } };
      }
      tokens.push({ kind: "string", value: filter.slice(i + 1, end), start: i });
      i = end + 1;
      continue;
    }
    if (/[A-Za-z0-9_.:!@*?-]/.test(ch)) {
      // Bare words may contain dots (fields, IPv4), colons (IPv6/MAC) and
      // wildcards; a digit-leading word like 1.1.1.1 must stay one token,
      // so numbers are classified only after the full word is captured.
      const match = /^[A-Za-z0-9_.:!@*?-]+/.exec(filter.slice(i));
      if (!match) return { error: { message: "unexpected character", position: i } };
      const text = match[0];
      if (/^[0-9]+$/.test(text)) {
        tokens.push({ kind: "number", value: Number(text), start: i });
      } else {
        tokens.push({ kind: "word", text, start: i });
      }
      i += text.length;
      continue;
    }
    return { error: { message: `unexpected character "${ch}"`, position: i } };
  }
  return { tokens };
}

// --- AST ----------------------------------------------------------------------

type Node =
  | { kind: "and"; left: Node; right: Node }
  | { kind: "or"; left: Node; right: Node }
  | { kind: "not"; inner: Node }
  | { kind: "protocol"; name: string; start: number }
  | { kind: "compare"; field: string; op: CompareOp; value: string; start: number };

type CompareOp = "==" | "!=" | ">" | ">=" | "<" | "<=" | "contains";

class Parser {
  private pos = 0;
  private readonly tokens: Token[];
  private readonly filter: string;

  constructor(tokens: Token[], filter: string) {
    this.tokens = tokens;
    this.filter = filter;
  }

  parse(): { node: Node } | { error: FilterPositionedError } {
    if (this.tokens.length === 0) {
      return { node: { kind: "and", left: { kind: "protocol", name: "", start: 0 }, right: { kind: "protocol", name: "", start: 0 } } };
    }
    const result = this.parseOr();
    if ("error" in result) return result;
    const token = this.tokens[this.pos];
    if (token) {
      return {
        error: {
          message: `unexpected "${this.filter.slice(token.start, token.start + tokenLength(token))}"`,
          position: token.start,
        },
      };
    }
    return result;
  }

  private parseOr(): { node: Node } | { error: FilterPositionedError } {
    let result = this.parseAnd();
    if ("error" in result) return result;
    while (this.peekWord("or")) {
      this.pos += 1;
      const right = this.parseAnd();
      if ("error" in right) return right;
      result = { node: { kind: "or", left: result.node, right: right.node } };
    }
    return result;
  }

  private parseAnd(): { node: Node } | { error: FilterPositionedError } {
    let result = this.parseNot();
    if ("error" in result) return result;
    while (this.peekWord("and")) {
      this.pos += 1;
      const right = this.parseNot();
      if ("error" in right) return right;
      result = { node: { kind: "and", left: result.node, right: right.node } };
    }
    return result;
  }

  private parseNot(): { node: Node } | { error: FilterPositionedError } {
    if (this.peekWord("not")) {
      this.pos += 1;
      const inner = this.parseNot();
      if ("error" in inner) return inner;
      return { node: { kind: "not", inner: inner.node } };
    }
    return this.parsePrimary();
  }

  private parsePrimary(): { node: Node } | { error: FilterPositionedError } {
    const token = this.tokens[this.pos];
    if (!token) {
      return { error: { message: "expression ended unexpectedly", position: this.filter.length } };
    }
    if (token.kind === "lparen") {
      this.pos += 1;
      const inner = this.parseOr();
      if ("error" in inner) return inner;
      const close = this.tokens[this.pos];
      if (!close || close.kind !== "rparen") {
        return { error: { message: "missing closing parenthesis", position: close ? close.start : this.filter.length } };
      }
      this.pos += 1;
      return inner;
    }
    // A comparison is a word followed by an operator (or the word-operator
    // "contains"). A bare word is a protocol name.
    if (token.kind === "word") {
      const next = this.tokens[this.pos + 1];
      const nextIsOp = next?.kind === "op";
      const nextIsContains = next?.kind === "word" && next.text.toLowerCase() === "contains";
      if (nextIsOp || nextIsContains) {
        const field = token.text.toLowerCase();
        let op: CompareOp;
        if (nextIsContains) {
          op = "contains";
          this.pos += 2;
        } else {
          op = (next as { kind: "op"; text: CompareOp }).text;
          this.pos += 2;
        }
        const value = this.tokens[this.pos];
        if (!value) {
          return { error: { message: `field "${field}" is missing a value`, position: this.filter.length } };
        }
        let text: string;
        if (value.kind === "string") {
          text = value.value;
          this.pos += 1;
        } else if (value.kind === "word" || value.kind === "number") {
          text = value.kind === "number" ? String(value.value) : value.text;
          this.pos += 1;
        } else {
          return { error: { message: `field "${field}" needs a value, not a bracket`, position: value.start } };
        }
        return { node: { kind: "compare", field, op, value: text, start: token.start } };
      }
      this.pos += 1;
      return { node: { kind: "protocol", name: token.text.toLowerCase(), start: token.start } };
    }
    return {
      error: {
        message: token.kind === "rparen" ? "unexpected closing parenthesis" : "unexpected token",
        position: token.start,
      },
    };
  }

  private peekWord(word: string): boolean {
    const token = this.tokens[this.pos];
    return token?.kind === "word" && token.text.toLowerCase() === word;
  }
}

function tokenLength(token: Token): number {
  switch (token.kind) {
    case "word":
      return token.text.length;
    case "number":
      return String(token.value).length;
    case "string":
      return token.value.length + 2;
    case "op":
      return token.text.length;
    default:
      return 1;
  }
}

// --- field evaluation ---------------------------------------------------------

/** Protocols that ride on TCP or UDP; the display protocol may be either. */
const TCP_FAMILY = ["tcp", "http", "tls", "ssh", "smtp"];
const UDP_FAMILY = ["udp", "dns", "dhcp", "ntp", "stun", "mdns", "llmnr"];

export const KNOWN_PROTOCOL_TOKENS = [
  "tcp", "udp", "http", "tls", "dns", "dhcp", "ntp", "stun", "mdns", "llmnr",
  "arp", "icmp", "icmpv6", "ipv6", "ip", "eth", "ssh", "smtp",
] as const;

export const KNOWN_FILTER_FIELDS = [
  "frame.number", "frame.len", "frame.time_relative",
  "ip.addr", "ip.src", "ip.dst", "ip.ttl",
  "ipv6.addr", "ipv6.src", "ipv6.dst",
  "eth.addr", "eth.src", "eth.dst",
  "tcp.port", "tcp.srcport", "tcp.dstport",
  "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.rst", "tcp.flags.psh", "tcp.flags.urg",
  "udp.port", "udp.srcport", "udp.dstport",
  "info",
] as const;

const TCP_FLAG_BITS: Record<string, { mask: number; name: string }> = {
  "tcp.flags.fin": { mask: 0x01, name: "FIN" },
  "tcp.flags.syn": { mask: 0x02, name: "SYN" },
  "tcp.flags.rst": { mask: 0x04, name: "RST" },
  "tcp.flags.psh": { mask: 0x08, name: "PSH" },
  "tcp.flags.ack": { mask: 0x10, name: "ACK" },
  "tcp.flags.urg": { mask: 0x20, name: "URG" },
};

function isIpv4(address: string): boolean {
  return address.includes(".") && !address.includes(":");
}

function isIpv6(address: string): boolean {
  return address.includes(":");
}

function layerOf(p: FilterPacket, label: string): string {
  const lower = label.toLowerCase();
  return p.layers.find((l) => l.label.toLowerCase() === lower)?.value ?? "";
}

function protocolFamily(protocol: string): string {
  const lower = protocol.toLowerCase();
  if (TCP_FAMILY.includes(lower) || lower.startsWith("tlsv")) return "tcp";
  if (UDP_FAMILY.includes(lower)) return "udp";
  if (lower === "arp") return "arp";
  if (lower === "icmp" || lower === "icmpv6") return "icmp";
  if (lower.startsWith("ipv6") || lower.startsWith("ipv6-")) return "ipv6";
  if (lower.startsWith("ip") && !lower.includes(":")) return "ip";
  return lower;
}

/** Numeric comparison against an integer value; false when not parseable. */
function compareNumber(actual: number | null, op: CompareOp, raw: string): boolean {
  if (actual === null) return false;
  const operand = Number(raw);
  if (!Number.isFinite(operand)) return false;
  switch (op) {
    case "==": return actual === operand;
    case "!=": return actual !== operand;
    case ">": return actual > operand;
    case ">=": return actual >= operand;
    case "<": return actual < operand;
    case "<=": return actual <= operand;
    default: return false;
  }
}

function compareString(actual: string, op: CompareOp, raw: string): boolean {
  switch (op) {
    case "==": return actual === raw;
    case "!=": return actual !== raw;
    case "contains": return actual.toLowerCase().includes(raw.toLowerCase());
    default: return false;
  }
}

function transportPorts(p: FilterPacket, family: "tcp" | "udp"): [string, string] | null {
  if (protocolFamily(p.protocol) !== family) return null;
  const source = layerOf(p, "source port");
  const destination = layerOf(p, "destination port");
  if (source === "" && destination === "") return null;
  return [source, destination];
}

/** Versioned display protocols (tlsv1.3, http2, …) are open-ended but shaped. */
function isKnownProtocolToken(name: string): boolean {
  if (([...KNOWN_PROTOCOL_TOKENS] as string[]).includes(name)) return true;
  return /^[a-z]+v[0-9]+([.][0-9]+)*$/.test(name);
}

function evaluateField(p: FilterPacket, field: string, op: CompareOp, raw: string): boolean {
  switch (field) {
    case "frame.number":
      return false; // rows do not carry their frame index into the filter model
    case "frame.len":
      return compareNumber(p.length, op, raw);
    case "frame.time_relative":
      return false; // relative seconds are not part of FilterPacket
    case "ip.addr":
      if (op === "contains") return false;
      return (isIpv4(p.source) && compareString(p.source, op, raw)) ||
        (isIpv4(p.destination) && compareString(p.destination, op, raw));
    case "ip.src":
      return isIpv4(p.source) && compareString(p.source, op, raw);
    case "ip.dst":
      return isIpv4(p.destination) && compareString(p.destination, op, raw);
    case "ip.ttl":
      return compareNumber(Number(layerOf(p, "ttl")) || null, op, raw);
    case "ipv6.addr":
      if (op === "contains") return false;
      return (isIpv6(p.source) && compareString(p.source, op, raw)) ||
        (isIpv6(p.destination) && compareString(p.destination, op, raw));
    case "ipv6.src":
      return isIpv6(p.source) && compareString(p.source, op, raw);
    case "ipv6.dst":
      return isIpv6(p.destination) && compareString(p.destination, op, raw);
    case "eth.addr":
    case "eth.src":
    case "eth.dst": {
      const ethernet = layerOf(p, "Ethernet II");
      const [src, dst] = ethernet.split(" → ");
      const target = field === "eth.src" ? src : field === "eth.dst" ? dst : undefined;
      if (field === "eth.addr") {
        return (src !== undefined && compareString(src, op, raw)) ||
          (dst !== undefined && compareString(dst, op, raw));
      }
      return target !== undefined && target !== "" && compareString(target, op, raw);
    }
    case "tcp.port":
    case "tcp.srcport":
    case "tcp.dstport": {
      const ports = transportPorts(p, "tcp");
      if (!ports) return false;
      const [src, dst] = ports;
      if (field === "tcp.srcport") return compareString(src, op, raw);
      if (field === "tcp.dstport") return compareString(dst, op, raw);
      return compareString(src, op, raw) || compareString(dst, op, raw);
    }
    case "udp.port":
    case "udp.srcport":
    case "udp.dstport": {
      const ports = transportPorts(p, "udp");
      if (!ports) return false;
      const [src, dst] = ports;
      if (field === "udp.srcport") return compareString(src, op, raw);
      if (field === "udp.dstport") return compareString(dst, op, raw);
      return compareString(src, op, raw) || compareString(dst, op, raw);
    }
    case "tcp.flags.syn":
    case "tcp.flags.ack":
    case "tcp.flags.fin":
    case "tcp.flags.rst":
    case "tcp.flags.psh":
    case "tcp.flags.urg": {
      if (protocolFamily(p.protocol) !== "tcp") return false;
      const flags = layerOf(p, "flags");
      const set = flags.toUpperCase().includes(TCP_FLAG_BITS[field].name);
      const wanted = raw === "1" || raw.toLowerCase() === "true";
      if (op === "==") return set === wanted;
      if (op === "!=") return set !== wanted;
      return false;
    }
    case "info":
      return compareString(p.info, op, raw);
    default:
      return false;
  }
}

function validateComparison(field: string, op: CompareOp, value: string, start: number): FilterPositionedError | null {
  if (!([...KNOWN_FILTER_FIELDS] as string[]).includes(field)) {
    return { message: `unknown field "${field}"`, position: start };
  }
  const numericFields = ["frame.len", "frame.number", "frame.time_relative", "ip.ttl", "tcp.port", "tcp.srcport", "tcp.dstport", "udp.port", "udp.srcport", "udp.dstport"];
  if (numericFields.includes(field)) {
    if (op === "contains") return { message: `field "${field}" does not support "contains"`, position: start };
    if (!/^[0-9]+$/.test(value)) return { message: `field "${field}" needs a number, got "${value}"`, position: start };
    return null;
  }
  const flagFields = Object.keys(TCP_FLAG_BITS);
  if (flagFields.includes(field)) {
    if (op !== "==" && op !== "!=") return { message: `flag field "${field}" supports == and != only`, position: start };
    if (!/^(0|1|true|false)$/i.test(value)) return { message: `flag field "${field}" needs 1, 0, true or false`, position: start };
    return null;
  }
  if (op === ">" || op === ">=" || op === "<" || op === "<=") {
    return { message: `field "${field}" does not support ordering`, position: start };
  }
  return null;
}

/**
 * Static validation walked once after parsing, so unknown protocols and bad
 * values surface immediately in the filter bar instead of failing silently
 * per row at evaluation time.
 */
function validateNode(node: Node): FilterPositionedError | null {
  switch (node.kind) {
    case "and":
    case "or":
      return validateNode(node.left) ?? validateNode(node.right);
    case "not":
      return validateNode(node.inner);
    case "protocol": {
      if (node.name !== "" && !isKnownProtocolToken(node.name)) {
        return {
          message: `"${node.name}" is neither a known protocol nor a filter expression`,
          position: node.start,
        };
      }
      return null;
    }
    case "compare":
      return validateComparison(node.field, node.op, node.value, node.start);
  }
}

function evalNode(p: FilterPacket, node: Node): boolean | FilterPositionedError {
  switch (node.kind) {
    case "and": {
      const left = evalNode(p, node.left);
      if (typeof left !== "boolean") return left;
      if (!left) return false;
      return evalNode(p, node.right);
    }
    case "or": {
      const left = evalNode(p, node.left);
      if (typeof left !== "boolean") return left;
      if (left) return true;
      return evalNode(p, node.right);
    }
    case "not": {
      const inner = evalNode(p, node.inner);
      if (typeof inner !== "boolean") return inner;
      return !inner;
    }
    case "protocol": {
      if (node.name === "") return true;
      if (!isKnownProtocolToken(node.name)) {
        return { message: `"${node.name}" is neither a known protocol nor a filter expression`, position: node.start };
      }
      const family = protocolFamily(p.protocol);
      const name = node.name;
      if (name === "ip") return family === "ip" || family === "tcp" || family === "udp" || family === "icmp";
      if (name === "icmp") return family === "icmp";
      if (name === "icmpv6") return p.protocol.toLowerCase().startsWith("icmpv6");
      if (name === "ipv6") return family === "ipv6";
      if (name === "eth") return p.layers.some((l) => l.label.toLowerCase() === "ethernet ii");
      return family === name || p.protocol.toLowerCase().startsWith(name);
    }
    case "compare": {
      const problem = validateComparison(node.field, node.op, node.value, node.start);
      if (problem) return problem;
      return evaluateField(p, node.field, node.op, node.value);
    }
  }
}

export type DisplayFilter = {
  ok: true;
  /** Evaluate the parsed filter against one dissected row. */
  matches: (p: FilterPacket) => boolean;
};

export type InvalidFilter = { ok: false; error: FilterPositionedError };

/** Parse once, evaluate many times — the packet list calls this per row. */
export function parseDisplayFilter(filter: string): DisplayFilter | InvalidFilter {
  const trimmed = filter.trim();
  if (trimmed === "") return { ok: true, matches: () => true };
  const tokens = tokenize(trimmed);
  if ("error" in tokens) return { ok: false, error: tokens.error };
  const parsed = new Parser(tokens.tokens, trimmed).parse();
  if ("error" in parsed) return { ok: false, error: parsed.error };
  const problem = validateNode(parsed.node);
  if (problem) return { ok: false, error: problem };
  return {
    ok: true,
    matches: (p: FilterPacket) => {
      const result = evalNode(p, parsed.node);
      return result === true; // a positioned error here means data outside validation caught it; treat as no-match
    },
  };
}

/** Backwards-compatible helper for callers that only need a boolean. */
export function matchesFilter(p: FilterPacket, filter: string): boolean {
  const parsed = parseDisplayFilter(filter);
  return parsed.ok && parsed.matches(p);
}

/** Visible syntax validation for the filter bar (§5.1). */
export function filterErrorOf(filter: string): FilterPositionedError | null {
  const parsed = parseDisplayFilter(filter);
  return parsed.ok ? null : parsed.error;
}

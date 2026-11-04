/**
 * Network feature model layer.
 * Arc 1 ships a deterministic sample capture derived from a synthetic DNS +
 * TCP + HTTP exchange so the three-pane layout runs on representative data.
 * PCAP/PCAPNG parsing and live capture move to the Rust core in arc 2
 * (Master Plan §5.1); this model's interfaces are written to survive that swap.
 */

export interface PacketRow {
  no: number;
  timeOffsetMs: number;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  info: string;
  colorHint: "dns" | "tcp" | "tls" | "http" | "arp" | "udp" | "icmp" | "ipv6" | "other";
}

export interface DetailNode {
  label: string;
  value?: string;
  children?: DetailNode[];
}

/** Deterministic pseudo-random bytes so the hex pane has stable content. */
export function sampleFrameBytes(seed: number, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let state = 0x1234abcd ^ (seed * 0x9e3779b9);
  for (let i = 0; i < length; i++) {
    state = (state * 1664525 + 1013904223) >>> 0;
    bytes[i] = (state >>> 24) & 0xff;
  }
  return bytes;
}

export const SAMPLE_PACKETS: PacketRow[] = [
  { no: 1, timeOffsetMs: 0, source: "192.168.1.24", destination: "192.168.1.1", protocol: "ARP", length: 42, info: "Who has 192.168.1.1? Tell 192.168.1.24", colorHint: "arp" },
  { no: 2, timeOffsetMs: 12, source: "192.168.1.24", destination: "1.1.1.1", protocol: "DNS", length: 73, info: "Standard query 0x8f2a A workbench.test", colorHint: "dns" },
  { no: 3, timeOffsetMs: 35, source: "1.1.1.1", destination: "192.168.1.24", protocol: "DNS", length: 121, info: "Standard query response A 10.0.0.42", colorHint: "dns" },
  { no: 4, timeOffsetMs: 41, source: "192.168.1.24", destination: "10.0.0.42", protocol: "TCP", length: 60, info: "49812 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460", colorHint: "tcp" },
  { no: 5, timeOffsetMs: 44, source: "10.0.0.42", destination: "192.168.1.24", protocol: "TCP", length: 60, info: "443 → 49812 [SYN, ACK] Seq=0 Ack=1 Win=65535", colorHint: "tcp" },
  { no: 6, timeOffsetMs: 45, source: "192.168.1.24", destination: "10.0.0.42", protocol: "TLSv1.3", length: 517, info: "Client Hello (SNI: workbench.test)", colorHint: "tls" },
  { no: 7, timeOffsetMs: 61, source: "10.0.0.42", destination: "192.168.1.24", protocol: "TLSv1.3", length: 5082, info: "Server Hello, Change Cipher Spec, Encrypted Extensions", colorHint: "tls" },
  { no: 8, timeOffsetMs: 140, source: "10.0.0.42", destination: "192.168.1.24", protocol: "TCP", length: 1514, info: "443 → 49812 [ACK] Seq=5032 Ack=518 Win=131712 Len=1460", colorHint: "tcp" },
  { no: 9, timeOffsetMs: 420, source: "192.168.1.24", destination: "10.0.0.80", protocol: "HTTP", length: 512, info: "GET /api/evidence HTTP/1.1 (plaintext lab host)", colorHint: "http" },
  { no: 10, timeOffsetMs: 438, source: "10.0.0.80", destination: "192.168.1.24", protocol: "HTTP", length: 1440, info: "HTTP/1.1 200 OK (application/json)", colorHint: "http" },
];

export const PROTOCOL_COLORS: Record<string, string> = {
  arp: "text-fg-muted",
  dns: "text-warn",
  tcp: "text-fg-dim",
  tls: "text-orange",
  http: "text-fg-dim",
  udp: "text-fg-muted",
  icmp: "text-warn",
  ipv6: "text-orange",
  other: "text-fg-muted",
};

export function detailTree(packet: PacketRow): DetailNode[] {
  const base: DetailNode[] = [
    {
      label: `Frame ${packet.no}`,
      value: `${packet.length} bytes captured`,
      children: [
        { label: "arrival", value: `+${packet.timeOffsetMs} ms` },
        { label: "coloring rule", value: packet.protocol.toLowerCase() },
      ],
    },
    {
      label: "Ethernet II",
      value: "src 3c:22:fb:9a:11:02 → dst 3c:22:fb:9a:10:01",
    },
    {
      label: "Internet Protocol Version 4",
      value: `${packet.source} → ${packet.destination}`,
      children: [
        { label: "ttl", value: "64" },
        { label: "flags", value: "0x4000, Don't fragment" },
      ],
    },
  ];
  if (packet.protocol === "TCP" || packet.protocol === "TLSv1.3" || packet.protocol === "HTTP") {
    base.push({
      label: "Transmission Control Protocol",
      value: packet.info,
      children: [
        { label: "source port", value: packet.source === "192.168.1.24" ? "49812" : "443" },
        { label: "destination port", value: packet.source === "192.168.1.24" ? "443" : "49812" },
        { label: "stream index", value: "0" },
      ],
    });
  }
  if (packet.protocol === "DNS") {
    base.push({ label: "Domain Name System", value: packet.info, children: [{ label: "questions", value: "1" }, { label: "answers", value: packet.destination === "192.168.1.24" ? "1" : "0" }] });
  }
  if (packet.protocol === "HTTP") {
    base.push({ label: "Hypertext Transfer Protocol", value: packet.info, children: [{ label: "line-based text", value: packet.info }] });
  }
  base.push({ label: "Payload / reassembled bytes", value: "arc 2: dissector engine" });
  return base;
}

export interface HostRow {
  host: string;
  ports: string;
  service: string;
  source: string;
  status: "up" | "filtered" | "down";
}

export const SAMPLE_HOSTS: HostRow[] = [
  { host: "10.0.0.42", ports: "443/tcp", service: "https (syn-ack)", source: "discovery profile A", status: "up" },
  { host: "10.0.0.80", ports: "80/tcp, 8080/tcp", service: "http (lab demo)", source: "discovery profile A", status: "up" },
  { host: "10.0.0.90", ports: "22/tcp", service: "ssh (filtered)", source: "discovery profile A", status: "filtered" },
];


// --- display filter + analysis helpers (pure, testable) -----------------------

export interface FilterPacket {
  source: string;
  destination: string;
  protocol: string;
  length: number;
  info: string;
  layers: { label: string; value: string }[];
}

/**
 * Display-filter language v2 lives in display-filter.ts: a real tokenizer +
 * parser supporting and/or/not, parentheses, ordering operators, `contains`,
 * tcp/udp port and flag fields, eth/ip/ipv6 address fields and visible syntax
 * validation. Re-exported here for the views.
 */
export {
  matchesFilter,
  parseDisplayFilter,
  filterErrorOf,
  KNOWN_FILTER_FIELDS,
  KNOWN_PROTOCOL_TOKENS,
  type DisplayFilter,
  type InvalidFilter,
  type FilterPositionedError,
} from "./display-filter.ts";

export interface Conversation {
  endpoints: [string, string];
  packets: number;
  bytes: number;
  protocols: string[];
}

export function conversationsOf(packets: FilterPacket[]): Conversation[] {
  const map = new Map<string, Conversation>();
  for (const p of packets) {
    const key = [p.source, p.destination].sort().join(" ↔ ");
    const entry = map.get(key) ?? { endpoints: [p.source, p.destination], packets: 0, bytes: 0, protocols: [] };
    entry.packets += 1;
    entry.bytes += p.length;
    if (!entry.protocols.includes(p.protocol)) entry.protocols.push(p.protocol);
    map.set(key, entry);
  }
  return [...map.values()].sort((a, b) => b.packets - a.packets);
}

export interface ProtocolStat {
  protocol: string;
  packets: number;
  bytes: number;
}

export function protocolStats(packets: FilterPacket[]): ProtocolStat[] {
  const map = new Map<string, ProtocolStat>();
  for (const p of packets) {
    const entry = map.get(p.protocol) ?? { protocol: p.protocol, packets: 0, bytes: 0 };
    entry.packets += 1;
    entry.bytes += p.length;
    map.set(p.protocol, entry);
  }
  return [...map.values()].sort((a, b) => b.packets - a.packets);
}

// --- protocol hierarchy, endpoints, IO graph (§5.1 statistics) ----------------

/**
 * Wireshark-style protocol hierarchy: every row contributes a protocol chain
 * derived from the actual dissection layer labels, so an HTTP row counts as
 * Ethernet → IPv4 → TCP → HTTP instead of a flat "HTTP" total. Label mapping
 * is bounded to what the Rust dissector emits today; unknown labels are
 * ignored rather than guessed.
 */
function protocolChainOf(p: FilterPacket): string[] {
  const labels = new Set(p.layers.map((l) => l.label.toLowerCase()));
  const chain: string[] = [];
  const push = (name: string) => {
    if (!chain.includes(name)) chain.push(name);
  };
  if (labels.has("ethernet ii") || labels.has("linux cooked capture")) push("eth");
  if (labels.has("address resolution protocol")) {
    push("arp");
    return chain;
  }
  if (labels.has("internet protocol version 4")) push("ip");
  if (labels.has("internet protocol version 6")) push("ipv6");
  const family = protocolFamilyOf(p.protocol);
  if (family === "tcp" || labels.has("transmission control protocol")) push("tcp");
  if (family === "udp" || labels.has("user datagram protocol")) push("udp");
  if (family === "icmp" || p.protocol.toLowerCase().startsWith("icmpv6")) push(p.protocol.toLowerCase().startsWith("icmpv6") ? "icmpv6" : "icmp");
  const leaf = p.protocol.toLowerCase();
  if (!["tcp", "udp", "ip", "ipv6", "icmp", "icmpv6"].includes(leaf) && !(leaf.startsWith("ip-") || leaf.startsWith("ipv6-") || leaf.startsWith("ipv4-") || leaf.endsWith("-truncated"))) {
    push(leaf);
  }
  return chain;
}

function protocolFamilyOf(protocol: string): string {
  const lower = protocol.toLowerCase();
  if (["tcp", "http", "tls", "ssh", "smtp"].includes(lower) || lower.startsWith("tlsv")) return "tcp";
  if (["udp", "dns", "dhcp", "ntp", "stun", "mdns", "llmnr"].includes(lower)) return "udp";
  if (lower === "icmp" || lower === "icmpv6") return "icmp";
  return lower;
}

export interface HierarchyNode {
  protocol: string;
  packets: number;
  bytes: number;
  children: HierarchyNode[];
}

/** Aggregation uses maps keyed by protocol name; output converts to arrays. */
type HierarchyLevel = Map<string, { packets: number; bytes: number; children: HierarchyLevel }>;

export function protocolHierarchy(packets: FilterPacket[]): HierarchyNode[] {
  const roots: HierarchyLevel = new Map();
  const sortLevel = (level: HierarchyLevel): HierarchyNode[] =>
    [...level.entries()]
      .map(([protocol, agg]) => ({
        protocol,
        packets: agg.packets,
        bytes: agg.bytes,
        children: sortLevel(agg.children),
      }))
      .sort((a, b) => b.packets - a.packets);
  for (const p of packets) {
    let level = roots;
    for (const name of protocolChainOf(p)) {
      let entry = level.get(name);
      if (!entry) {
        entry = { packets: 0, bytes: 0, children: new Map() };
        level.set(name, entry);
      }
      entry.packets += 1;
      entry.bytes += p.length;
      level = entry.children;
    }
  }
  return sortLevel(roots);
}

export interface EndpointStat {
  address: string;
  /** mac | ip4 | ip6 — Wireshark's endpoint tabs split by address family. */
  family: "mac" | "ip4" | "ip6";
  packets: number;
  bytes: number;
}

function endpointFamily(address: string): EndpointStat["family"] | null {
  if (/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i.test(address)) return "mac";
  if (address.includes(":")) return address.includes("::") || /^([0-9a-f]{1,4}:){2,}[0-9a-f]*$/i.test(address) ? "ip6" : null;
  if (address.includes(".")) return /^\d{1,3}(\.\d{1,3}){3}$/.test(address) ? "ip4" : null;
  return null;
}

/** MAC endpoints come from the Ethernet II layer value "src → dst". */
export function endpointsOf(packets: FilterPacket[]): EndpointStat[] {
  const map = new Map<string, EndpointStat>();
  const record = (address: string, bytes: number) => {
    const family = endpointFamily(address);
    if (!family) return;
    const entry = map.get(address) ?? { address, family, packets: 0, bytes: 0 };
    entry.packets += 1;
    entry.bytes += bytes;
    map.set(address, entry);
  };
  for (const p of packets) {
    const ethernet = p.layers.find((l) => l.label.toLowerCase() === "ethernet ii")?.value ?? "";
    const [srcMac, dstMac] = ethernet.split(" → ");
    if (srcMac && dstMac) {
      record(srcMac, p.length);
      record(dstMac, p.length);
    }
    record(p.source, p.length);
    record(p.destination, p.length);
  }
  const familyOrder: Record<EndpointStat["family"], number> = { ip4: 0, ip6: 1, mac: 2 };
  return [...map.values()].sort(
    (a, b) => familyOrder[a.family] - familyOrder[b.family] || b.packets - a.packets,
  );
}

export interface IoBucket {
  /** Bucket start in ms relative to the first packet. */
  fromMs: number;
  packets: number;
  bytes: number;
}

/**
 * Time-bucketed series for the IO graph. Buckets span the capture's own time
 * range; an empty or single-instant capture yields one bucket so the graph
 * never divides by zero.
 */
export function ioSeriesOf(packets: FilterPacket[], bucketCount = 60): IoBucket[] {
  if (packets.length === 0) return [];
  const times = packets.map((p) => (p as { time_ms?: number }).time_ms ?? 0);
  const min = Math.min(...times);
  const max = Math.max(...times);
  const span = Math.max(max - min, 1);
  const count = Math.max(1, Math.min(bucketCount, 240));
  const width = span / count;
  const buckets: IoBucket[] = Array.from({ length: count }, (_, i) => ({
    fromMs: min + i * width,
    packets: 0,
    bytes: 0,
  }));
  for (const p of packets) {
    const time = (p as { time_ms?: number }).time_ms ?? min;
    const index = Math.min(count - 1, Math.max(0, Math.floor((time - min) / width)));
    buckets[index].packets += 1;
    buckets[index].bytes += p.length;
  }
  return buckets;
}

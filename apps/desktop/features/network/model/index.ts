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
  colorHint: "dns" | "tcp" | "tls" | "http" | "arp";
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

export const PROTOCOL_COLORS: Record<PacketRow["colorHint"], string> = {
  arp: "text-fg-muted",
  dns: "text-warn",
  tcp: "text-fg-dim",
  tls: "text-orange",
  http: "text-blue",
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

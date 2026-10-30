/**
 * Network feature controller layer.
 * Pure selection/filter transitions for the packet studio. Display-filter
 * compilation and capture control move to the Rust core in arc 2.
 */
import { SAMPLE_PACKETS, type PacketRow } from "../model";

export function filterPackets(packets: PacketRow[], query: string): PacketRow[] {
  const q = query.trim().toLowerCase();
  if (!q) return packets;
  // Arc-1 convenience match across columns; real display-filter syntax
  // (e.g. "tcp.port == 443") lands with the dissector engine.
  return packets.filter(
    (p) =>
      p.source.toLowerCase().includes(q) ||
      p.destination.toLowerCase().includes(q) ||
      p.protocol.toLowerCase().includes(q) ||
      p.info.toLowerCase().includes(q),
  );
}

export function selectPacket(packets: PacketRow[] = SAMPLE_PACKETS, no: number): PacketRow | undefined {
  return packets.find((p) => p.no === no);
}

export function formatTime(offsetMs: number): string {
  return `${(offsetMs / 1000).toFixed(6)}`;
}

"use client";

import type { ReactNode } from "react";

/** One presentation for real PCAP rows and case-authorized live frame summaries. */
export interface PacketTableRow {
  index: number;
  time?: string;
  source: string | null;
  destination: string | null;
  protocol?: string | null;
  length: number;
  info: string;
  protocolColor?: string;
}

export function PacketTable({
  rows, selectedIndex, onSelect, topSpacer = 0, bottomSpacer = 0, empty,
}: {
  rows: readonly PacketTableRow[];
  selectedIndex: number | null;
  onSelect: (index: number) => void;
  topSpacer?: number;
  bottomSpacer?: number;
  empty?: ReactNode;
}) {
  return (
    <table className="data-table cd-packet-table w-full" aria-label="Packet list">
      <thead>
        <tr>
          <th className="w-12">No.</th>
          <th className="w-24">Time</th>
          <th className="w-36">Source</th>
          <th className="w-36">Destination</th>
          <th className="w-24">Protocol</th>
          <th className="w-20">Length</th>
          <th>Info</th>
        </tr>
      </thead>
      <tbody>
        {topSpacer > 0 && <tr aria-hidden="true"><td colSpan={7} style={{ height: topSpacer, padding: 0, border: 0 }} /></tr>}
        {rows.map((packet) => (
          <tr key={packet.index} tabIndex={0} aria-selected={packet.index === selectedIndex}
            onClick={() => onSelect(packet.index)}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                onSelect(packet.index);
              }
            }}
            className={`h-[26px] cursor-pointer focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-[-1px] focus-visible:outline-ring ${packet.index === selectedIndex ? "selected" : ""}`}>
            <td className="text-fg-muted">{packet.index + 1}</td>
            <td className="text-fg-dim">{packet.time ?? "—"}</td>
            <td className="text-fg">{packet.source ?? "—"}</td>
            <td className="text-fg">{packet.destination ?? "—"}</td>
            <td className={packet.protocolColor ?? "text-fg-dim"}>{packet.protocol ?? "—"}</td>
            <td>{packet.length}</td>
            <td className="text-fg-dim">{packet.info}</td>
          </tr>
        ))}
        {bottomSpacer > 0 && <tr aria-hidden="true"><td colSpan={7} style={{ height: bottomSpacer, padding: 0, border: 0 }} /></tr>}
        {rows.length === 0 && !topSpacer && !bottomSpacer && (
          <tr><td colSpan={7} className="text-center text-fg-muted">{empty ?? "No packets in this view"}</td></tr>
        )}
      </tbody>
    </table>
  );
}

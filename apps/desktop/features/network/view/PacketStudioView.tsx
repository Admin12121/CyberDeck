"use client";
import { useEffect, useMemo, useState } from "react";
import { ChevronRight, FolderOpen, Play, ShieldAlert, Square } from "lucide-react";
import { Chip, EmptyState, Pane, Resizer, Select, TextInput, ToolButton } from "@ds/panes";
import { hexDump } from "@lib/hex";
import {
  isDesktop,
  pcapFollowStream,
  pcapOpenDialog,
  pcapPacketBytes,
  type HexResponseWire,
  type PcapOpenWire,
  type PcapPacketWire,
  type StreamChunkWire,
} from "@lib/ipc";
import { useWorkbench } from "@state/workbench";
import type { ToolId } from "@features/registry";
import {
  PROTOCOL_COLORS,
  SAMPLE_HOSTS,
  SAMPLE_PACKETS,
  conversationsOf,
  detailTree,
  matchesFilter,
  protocolStats,
  sampleFrameBytes,
  type DetailNode,
} from "../model";

type DisplayPacket = PcapPacketWire & { sample?: boolean };

const SAMPLE_DISPLAY: DisplayPacket[] = SAMPLE_PACKETS.map((p, i) => ({
  index: i,
  time_ms: p.timeOffsetMs,
  source: p.source,
  destination: p.destination,
  protocol: p.protocol,
  length: p.length,
  info: p.info,
  color_hint: p.colorHint,
  stream_id: null,
  layers: [],
  sample: true,
}));

export function PacketStudioView() {
  const desktop = isDesktop();
  const [capture, setCapture] = useState<PcapOpenWire | null>(null);
  const [openError, setOpenError] = useState<string | null>(null);
  const [opening, setOpening] = useState(false);
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState(0);
  const [tab, setTab] = useState<"packets" | "conversations" | "statistics" | "streams">("packets");
  const [packetBytes, setPacketBytes] = useState<HexResponseWire | null>(null);
  // null: details and bytes share the row evenly; dragging pins px.
  const [detailsWidth, setDetailsWidth] = useState<number | null>(null);

  const packets = capture?.packets ?? SAMPLE_DISPLAY;

  const openCapture = async () => {
    setOpening(true);
    setOpenError(null);
    try {
      const wire = await pcapOpenDialog();
      setCapture(wire);
      setSelected(0);
      setPacketBytes(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message !== "cancelled") setOpenError(message);
    } finally {
      setOpening(false);
    }
  };

  useEffect(() => {
    if (!capture) return;
    let cancelled = false;
    setPacketBytes(null);
    pcapPacketBytes(selected, 0, 512)
      .then((data) => {
        if (!cancelled) setPacketBytes(data);
      })
      .catch((err) => {
        if (!cancelled) console.error("pcap_packet_bytes failed:", err);
      });
    return () => {
      cancelled = true;
    };
  }, [capture, selected]);

  const filtered = useMemo(() => {
    const q = filter.trim();
    if (!q) return packets;
    return packets.filter((p) => matchesFilter(p, q));
  }, [packets, filter]);

  const current = filtered.find((p) => p.index === selected) ?? filtered[0];
  const sampleBytes = useMemo(
    () => (!capture && current ? sampleFrameBytes(current.index + 1, Math.min(current.length, 160)) : new Uint8Array()),
    [capture, current],
  );

  const timeLabel = (ms: number) => `${(ms / 1000).toFixed(6)}`;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-line bg-sidebar px-2">
        <ToolButton
          onClick={() => void openCapture()}
          disabled={!desktop || opening}
          title={desktop ? "Open a classic pcap capture, dissected by the native engine" : "Opening captures requires the desktop runtime"}
        >
          <FolderOpen size={11} /> {opening ? "opening…" : "Open…"}
        </ToolButton>
        <ToolButton disabled title="Live capture requires platform driver clearance (§7.2)">
          <Play size={11} /> Capture
        </ToolButton>
        <TextInput
          value={filter}
          onChange={setFilter}
          placeholder="display filter (tcp.port == 443)"
          ariaLabel="Display filter"
          className="min-w-0 flex-1"
        />
        {capture ? (
          <Chip tone="ok">{capture.file_name}: {capture.packet_count} packets</Chip>
        ) : (
          <Chip>sample capture</Chip>
        )}
      </div>
      {openError ? (
        <div className="border-b border-err/50 bg-err/10 px-2 py-1 font-mono text-[10px] text-err">{openError}</div>
      ) : null}
      {capture?.malformed_tail ? (
        <div className="border-b border-warn/40 bg-warn/10 px-2 py-1 font-mono text-[10px] text-warn">
          capture has a malformed trailing record; packets before it loaded
        </div>
      ) : null}

      <div className="flex min-h-0 flex-1 flex-col">
        <div className="flex min-h-0 flex-[5] flex-col overflow-hidden border-b border-line">
          {tab === "packets" ? (
            <table className="data-table">
              <thead>
                <tr>
                  <th className="w-10">No.</th>
                  <th className="w-24">Time</th>
                  <th className="w-32">Source</th>
                  <th className="w-32">Destination</th>
                  <th className="w-20">Protocol</th>
                  <th className="w-16">Length</th>
                  <th>Info</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((p) => (
                  <tr
                    key={p.index}
                    onClick={() => setSelected(p.index)}
                    className={`cursor-pointer ${p.index === current?.index ? "selected" : ""}`}
                  >
                    <td className="text-fg-muted">{p.index + 1}</td>
                    <td>{timeLabel(p.time_ms)}</td>
                    <td className="text-fg">{p.source}</td>
                    <td className="text-fg">{p.destination}</td>
                    <td className={PROTOCOL_COLORS[p.color_hint] ?? "text-fg-dim"}>{p.protocol}</td>
                    <td>{p.length}</td>
                    <td className="text-fg-dim">{p.info}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : tab === "conversations" ? (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Endpoint A</th>
                  <th>Endpoint B</th>
                  <th className="w-16">Packets</th>
                  <th className="w-24">Bytes</th>
                  <th>Protocols</th>
                </tr>
              </thead>
              <tbody>
                {conversationsOf(filtered).map((c) => (
                  <tr key={c.endpoints.join(" ")}>
                    <td className="text-fg">{c.endpoints[0]}</td>
                    <td className="text-fg">{c.endpoints[1]}</td>
                    <td>{c.packets}</td>
                    <td>{c.bytes}</td>
                    <td className="text-fg-muted">{c.protocols.join(", ")}</td>
                  </tr>
                ))}
                {conversationsOf(filtered).length === 0 ? (
                  <tr><td colSpan={5} className="text-center text-fg-muted">no conversations in the current view</td></tr>
                ) : null}
              </tbody>
            </table>
          ) : tab === "statistics" ? (
            <table className="data-table">
              <thead>
                <tr>
                  <th className="w-32">Protocol</th>
                  <th className="w-24">Packets</th>
                  <th className="w-28">Bytes</th>
                  <th>Share of bytes</th>
                </tr>
              </thead>
              <tbody>
                {protocolStats(filtered).map((stat) => {
                  const totalBytes = filtered.reduce((sum, item) => sum + item.length, 0) || 1;
                  return (
                    <tr key={stat.protocol}>
                      <td className={PROTOCOL_COLORS[stat.protocol.toLowerCase()] ?? "text-fg-dim"}>{stat.protocol}</td>
                      <td>{stat.packets}</td>
                      <td>{stat.bytes}</td>
                      <td>
                        <div className="h-1.5 w-full max-w-48 border border-line bg-app">
                          <div className="h-full bg-orange" style={{ width: `${Math.round((stat.bytes / totalBytes) * 100)}%` }} />
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <FollowStreamView packets={filtered} />
          )}
        </div>

        <div className="flex min-h-0 flex-[3]">
          <div aria-label="Packet details container" className="flex min-w-0 flex-1 flex-col overflow-hidden bg-panel">
            <div className="flex h-8 shrink-0 items-center border-b border-line bg-sidebar px-2 text-[10px] font-medium uppercase tracking-wider text-fg-muted">
              Packet details: {current ? `frame ${current.index + 1}` : "no selection"}
            </div>
            <div className="min-h-0 flex-1 overflow-auto p-1">
              {current ? (
                capture ? (
                  current.layers.map((layer, i) => (
                    <DetailBranch key={i} node={{ label: layer.label, value: layer.value }} depth={0} />
                  ))
                ) : (
                  detailTree(SAMPLE_PACKETS[current.index]).map((node, i) => <DetailBranch key={i} node={node} depth={0} />)
                )
              ) : null}
            </div>
          </div>
          <Resizer
            direction="horizontal"
            ariaLabel="Resize packet details"
            value={detailsWidth ?? 0}
            onChange={setDetailsWidth}
            min={240}
            max={720}
            onDragStart={() => {
              if (detailsWidth === null) {
                const left = document.querySelector('div[aria-label="Packet details container"]');
                const measured = Math.round((left?.getBoundingClientRect().width ?? 0));
                setDetailsWidth(measured);
                return measured;
              }
            }}
          />
          <div className="flex min-h-0 flex-1 flex-col overflow-hidden bg-panel" style={detailsWidth === null ? undefined : { width: detailsWidth }}>
            <div className="flex h-8 shrink-0 items-center border-b border-line bg-sidebar px-2 text-[10px] font-medium uppercase tracking-wider text-fg-muted">
              Packet bytes (offset · hex · ascii)
            </div>
            <div className="min-h-0 flex-1 overflow-auto">
              {capture && packetBytes ? (
                <pre className="p-1 font-mono text-[11px] leading-relaxed text-fg-dim">
                  {packetBytes.rows.map((row) => (
                    <div key={row.offset}>
                      <span className="text-fg-muted">{row.offset.toString(16).padStart(4, "0")}</span>
                      {"  "}
                      {row.hex}
                      {"  "}
                      <span className="text-orange">{row.ascii}</span>
                    </div>
                  ))}
                </pre>
              ) : !capture ? (
                <pre className="p-1 font-mono text-[11px] leading-relaxed text-fg-dim">
                  {hexDump(sampleBytes).map((row) => (
                    <div key={row.offset}>
                      <span className="text-fg-muted">{row.offset.toString(16).padStart(4, "0")}</span>
                      {"  "}
                      {row.hex}
                      {"  "}
                      <span className="text-orange">{row.ascii}</span>
                    </div>
                  ))}
                </pre>
              ) : null}
            </div>
          </div>
        </div>
      </div>

      <div className="flex h-8 shrink-0 items-center gap-1 border-t border-line bg-sidebar px-2">
        {(["packets", "conversations", "statistics", "streams"] as const).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={`h-5 border px-2 font-mono text-[10px] uppercase tracking-wide ${
              tab === t ? "border-orange/50 text-orange" : "border-transparent text-fg-muted hover:text-fg"
            }`}
          >
            {t}
          </button>
        ))}
      </div>
    </div>
  );
}

function DetailBranch({ node, depth }: { node: DetailNode; depth: number }) {
  const [open, setOpen] = useState(depth < 2);
  const hasChildren = Boolean(node.children?.length);
  return (
    <div style={{ paddingLeft: depth * 12 }}>
      <button
        type="button"
        onClick={() => hasChildren && setOpen((v) => !v)}
        className="flex w-full items-center gap-1 py-px text-left font-mono text-[11px] hover:bg-raised"
      >
        {hasChildren ? (
          <ChevronRight size={11} className={`shrink-0 text-fg-muted transition-transform ${open ? "rotate-90" : ""}`} />
        ) : (
          <span className="w-[11px] shrink-0" />
        )}
        <span className="text-fg">{node.label}</span>
        {node.value ? <span className="truncate text-fg-muted">: {node.value}</span> : null}
      </button>
      {open && hasChildren ? node.children!.map((child, i) => <DetailBranch key={i} node={child} depth={depth + 1} />) : null}
    </div>
  );
}

// ---------------------------------------------------------- follow stream ---

function FollowStreamView({ packets }: { packets: DisplayPacket[] }) {
  const desktop = isDesktop();
  const withStream = packets.filter((p) => p.stream_id);
  const [selected, setSelected] = useState<string | null>(null);
  const [chunks, setChunks] = useState<StreamChunkWire[] | null>(null);

  const streams = useMemo(() => {
    const map = new Map<string, { id: string; label: string; packets: number }>();
    for (const p of withStream) {
      const entry = map.get(p.stream_id!);
      if (entry) entry.packets += 1;
      else map.set(p.stream_id!, { id: p.stream_id!, label: p.source + " <-> " + p.destination, packets: 1 });
    }
    return [...map.values()];
  }, [withStream]);

  useEffect(() => {
    setChunks(null);
    if (!selected) return;
    let cancelled = false;
    pcapFollowStream(selected)
      .then((data) => {
        if (!cancelled) setChunks(data);
      })
      .catch((err) => {
        if (!cancelled) console.error("pcap_follow_stream failed:", err);
      });
    return () => {
      cancelled = true;
    };
  }, [selected]);

  if (!desktop) {
    return (
      <EmptyState title="Follow stream" detail="stream reassembly runs in the desktop runtime against opened captures" badge="follow stream" />
    );
  }
  if (streams.length === 0) {
    return (
      <EmptyState title="No TCP/UDP streams" detail="open a capture with TCP or UDP traffic; streams build from dissected ports" badge="follow stream" />
    );
  }
  return (
    <div className="flex h-full min-h-0">
      <div className="w-80 shrink-0 overflow-auto border-r border-line bg-sidebar p-1">
        {streams.map((stream) => (
          <button
            key={stream.id}
            type="button"
            onClick={() => setSelected(stream.id)}
            className={"block w-full truncate px-2 py-1 text-left font-mono text-[10px] " + (
              selected === stream.id ? "bg-orange-dim text-orange" : "text-fg-dim hover:bg-raised hover:text-fg"
            )}
          >
            {stream.label} · {stream.packets} pkt
          </button>
        ))}
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-2 font-mono text-[11px] leading-relaxed">
        {chunks === null ? (
          <div className="text-fg-muted">select a stream…</div>
        ) : chunks.length === 0 ? (
          <div className="text-fg-muted">no payload bytes in this stream</div>
        ) : (
          chunks.map((chunk, i) => (
            <div key={i} className="whitespace-pre-wrap break-all">
              <span className={chunk.dir === "A" ? "text-blue" : "text-orange"}>[{chunk.dir}] </span>
              <span className="text-fg">{chunk.text}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}


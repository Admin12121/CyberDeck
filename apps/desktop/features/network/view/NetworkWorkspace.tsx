"use client";
/**
 * Network feature view layer.
 * Packet Analysis: three linked panes over a real capture opened through the
 * native dialog, dissected by the Rust packet engine (hacktool-packet);
 * deterministic samples keep the layout developable in the browser.
 * Network Lab: gated active-operations mode. Scanning: Zenmap-style studio
 * wired to the shared job pipeline (Master Plan §5.1, §5.3).
 */
import { useEffect, useMemo, useState } from "react";
import { ChevronRight, FolderOpen, Play, ShieldAlert, Square } from "lucide-react";
import { Chip, EmptyState, Pane, Select, TextInput, ToolButton } from "@ds/panes";
import { hexDump } from "@lib/hex";
import { isDesktop, pcapOpenDialog, pcapPacketBytes, type HexResponseWire, type PcapOpenWire, type PcapPacketWire } from "@lib/ipc";
import { useWorkbench } from "@state/workbench";
import type { ToolId } from "@features/registry";
import {
  PROTOCOL_COLORS,
  SAMPLE_HOSTS,
  SAMPLE_PACKETS,
  detailTree,
  sampleFrameBytes,
  type DetailNode,
} from "../model";

/** All network tools stay mounted; hidden views keep their state. */
export function NetworkWorkspace({ tool }: { tool: ToolId }) {
  const show = (id: ToolId) => (tool === id ? "h-full" : "hidden h-full");
  return (
    <>
      <div className={show("network.packet")}><PacketStudioView /></div>
      <div className={show("network.lab")}><NetworkLabView /></div>
      <div className={show("network.scan")}><ScanView /></div>
    </>
  );
}

// --------------------------------------------------------- packet studio ---

type DisplayPacket = PcapPacketWire & { sample: boolean };

const SAMPLE_DISPLAY: DisplayPacket[] = SAMPLE_PACKETS.map((p, i) => ({
  index: i,
  time_ms: p.timeOffsetMs,
  source: p.source,
  destination: p.destination,
  protocol: p.protocol,
  length: p.length,
  info: p.info,
  color_hint: p.colorHint,
  layers: [],
  sample: true,
}));

function PacketStudioView() {
  const desktop = isDesktop();
  const [capture, setCapture] = useState<PcapOpenWire | null>(null);
  const [openError, setOpenError] = useState<string | null>(null);
  const [opening, setOpening] = useState(false);
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState(0);
  const [tab, setTab] = useState<"packets" | "conversations" | "statistics" | "streams">("packets");
  const [packetBytes, setPacketBytes] = useState<HexResponseWire | null>(null);

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
    const q = filter.trim().toLowerCase();
    if (!q) return packets;
    return packets.filter(
      (p) =>
        p.source.toLowerCase().includes(q) ||
        p.destination.toLowerCase().includes(q) ||
        p.protocol.toLowerCase().includes(q) ||
        p.info.toLowerCase().includes(q),
    );
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
        <Select value="" onChange={() => {}} options={[{ value: "", label: "interface: arc 4" }]} ariaLabel="Capture interface" />
        <span className="mx-1 h-4 w-px bg-line" />
        <div className="flex min-w-0 flex-1 items-center gap-1">
          <span className="font-mono text-[10px] uppercase text-fg-muted">display filter</span>
          <TextInput
            value={filter}
            onChange={setFilter}
            placeholder="column match; arc 4 adds filter syntax"
            ariaLabel="Display filter"
            className="min-w-0 flex-1"
          />
          <Chip tone={filter ? "ok" : "muted"}>{filter ? "matching" : "no filter"}</Chip>
        </div>
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
            <EmptyState title="Conversations" detail="Endpoint and conversation matrices arrive with the statistics engine (arc 4)." badge="packet studio" />
          ) : tab === "statistics" ? (
            <EmptyState title="Statistics" detail="Protocol hierarchy, I/O graphs and expert information arrive in arc 4." badge="packet studio" />
          ) : (
            <EmptyState title="Follow stream" detail="TCP/UDP/HTTP stream reassembly with provenance extraction lands arc 4." badge="packet studio" />
          )}
        </div>

        <div className="flex min-h-0 flex-[3] flex-col overflow-hidden border-b border-line bg-panel">
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

        <div className="flex min-h-0 flex-[3] flex-col overflow-hidden bg-panel">
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
        <span className="ml-auto font-mono text-[10px] text-fg-muted">
          {capture
            ? `engine: hacktool-packet (rust) · ${capture.shown} shown`
            : "open a pcap for native dissection"}
        </span>
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

// ------------------------------------------------------------ network lab ---

function NetworkLabView() {
  return (
    <div className="flex h-full min-h-0 items-center justify-center bg-app p-6">
      <div className="max-w-xl border border-orange/40 bg-panel">
        <div className="flex items-center gap-2 border-b border-line bg-orange-dim px-3 py-2">
          <ShieldAlert size={16} className="text-orange" />
          <span className="text-xs font-medium uppercase tracking-wide text-orange">Active network operations (gated)</span>
        </div>
        <div className="space-y-3 p-4 text-xs leading-relaxed text-fg-dim">
          <p>
            Network Lab hosts Ettercap-inspired interaction modes: host discovery, traffic inspection and
            on-path analysis for authorized lab scopes only. It never runs silently and never mixes into
            passive evidence without labels (Master Plan §5.1).
          </p>
          <ul className="space-y-1 font-mono text-[11px] text-fg-muted">
            <li>requires a configured authorized scope (CIDR / host set)</li>
            <li>requires a statement of authorization per session</li>
            <li>requires compatible privileges per OS (gate shown before enabling)</li>
            <li>emergency stop visible whenever any operation is armed</li>
          </ul>
          <div className="flex items-center gap-2 pt-1">
            <ToolButton disabled title="Scope configuration, engine integration arc 4">Configure scope</ToolButton>
            <ToolButton disabled title="Ettercap capability vetting, arc 4">Enable lab mode</ToolButton>
            <Chip>arc 4</Chip>
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- scanning ---

function ScanView() {
  const wb = useWorkbench();
  const [target, setTarget] = useState("10.0.0.0/28");
  const [profile, setProfile] = useState("discovery");

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-line bg-sidebar px-2">
        <span className="font-mono text-[10px] uppercase text-fg-muted">target</span>
        <TextInput value={target} onChange={setTarget} placeholder="host / CIDR / target set" ariaLabel="Scan target" className="w-56" />
        <span className="font-mono text-[10px] uppercase text-fg-muted">profile</span>
        <Select
          value={profile}
          onChange={setProfile}
          options={[
            { value: "discovery", label: "Discovery (host/port)" },
            { value: "service", label: "Service + version" },
            { value: "web", label: "Web review (engine: arc 4)" },
            { value: "templates", label: "Template checks (engine: arc 4)" },
          ]}
          ariaLabel="Scan profile"
        />
        <ToolButton tone="primary" onClick={wb.runDemoJob} title="Runs the shared job pipeline demo; scan engines arrive arc 4">
          <Play size={11} /> Run
        </ToolButton>
        <ToolButton onClick={wb.toggleDock} title="Open the jobs dock (Ctrl+J)">
          <Square size={11} /> Jobs
        </ToolButton>
        <span className="ml-auto font-mono text-[10px] text-fg-muted">
          engines: nmap-family vetting in progress (NPSL review); jobs are live
        </span>
      </div>
      <div className="flex min-h-0 flex-1">
        <Pane title="Hosts / services" className="min-w-0 flex-1">
          <table className="data-table">
            <thead>
              <tr>
                <th>Host</th>
                <th>Ports</th>
                <th>Service</th>
                <th>Source</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {SAMPLE_HOSTS.map((host) => (
                <tr key={host.host}>
                  <td className="text-fg">{host.host}</td>
                  <td>{host.ports}</td>
                  <td className="text-fg-dim">{host.service}</td>
                  <td className="text-fg-muted">{host.source}</td>
                  <td>
                    <Chip tone={host.status === "up" ? "ok" : host.status === "filtered" ? "blue" : "muted"}>{host.status}</Chip>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Pane>
        <Pane title="Run output (raw + provenance)" className="w-80 shrink-0">
          <div className="p-2 font-mono text-[11px] leading-relaxed text-fg-muted">
            <div className="text-fg-dim">$ profile={profile} target={target}</div>
            <div className="mt-1">raw engine output, scan diff and export land arc 4;</div>
            <div>every finding keeps engine id/version and policy in</div>
            <div>provenance (Master Plan §5.3).</div>
          </div>
        </Pane>
      </div>
    </div>
  );
}

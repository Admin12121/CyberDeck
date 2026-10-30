"use client";
/**
 * Network feature view layer.
 * Packet Analysis: three linked panes over the sample capture (list → details
 * → bytes with selection sync). Network Lab: gated active-operations mode.
 * Scanning: Zenmap-style target/profile studio wired to the shared job
 * pipeline. Engine integration arrives arc 2/3 (Master Plan §5.1, §5.3).
 */
import { useMemo, useState } from "react";
import { ChevronRight, Play, ShieldAlert, Square } from "lucide-react";
import { Chip, EmptyState, Pane, Select, TextInput, ToolButton } from "@ds/panes";
import { hexDump } from "@lib/hex";
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
import { filterPackets, formatTime } from "../controller";

export function NetworkWorkspace({ tool }: { tool: ToolId }) {
  if (tool === "network.lab") return <NetworkLabView />;
  if (tool === "network.scan") return <ScanView />;
  return <PacketStudioView />;
}

// --------------------------------------------------------- packet studio ---

function PacketStudioView() {
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState(SAMPLE_PACKETS[1].no);
  const [tab, setTab] = useState<"packets" | "conversations" | "statistics" | "streams">("packets");

  const packets = useMemo(() => filterPackets(SAMPLE_PACKETS, filter), [filter]);
  const packet = packets.find((p) => p.no === selected) ?? packets[0];
  const bytes = useMemo(() => (packet ? sampleFrameBytes(packet.no, Math.min(packet.length, 160)) : new Uint8Array()), [packet]);
  const rows = useMemo(() => hexDump(bytes), [bytes]);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-line bg-sidebar px-2">
        <ToolButton disabled title="Open capture, PCAP-PCAPNG engine lands arc 2">Open…</ToolButton>
        <ToolButton disabled title="Live capture requires platform driver clearance (§7.2)">
          <Play size={11} /> Capture
        </ToolButton>
        <Select value="" onChange={() => {}} options={[{ value: "", label: "interface: arc 2" }]} ariaLabel="Capture interface" />
        <span className="mx-1 h-4 w-px bg-line" />
        <div className="flex min-w-0 flex-1 items-center gap-1">
          <span className="font-mono text-[10px] uppercase text-fg-muted">display filter</span>
          <TextInput
            value={filter}
            onChange={setFilter}
            placeholder="tcp · dns · 10.0.0.42 (column match; arc 2 adds filter syntax)"
            ariaLabel="Display filter"
            className="min-w-0 flex-1"
          />
          <Chip tone={filter ? "ok" : "muted"}>{filter ? "matching" : "no filter"}</Chip>
        </div>
      </div>

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
                {packets.map((p) => (
                  <tr
                    key={p.no}
                    onClick={() => setSelected(p.no)}
                    className={`cursor-pointer ${p.no === packet?.no ? "selected" : ""}`}
                  >
                    <td className="text-fg-muted">{p.no}</td>
                    <td>{formatTime(p.timeOffsetMs)}</td>
                    <td className="text-fg">{p.source}</td>
                    <td className="text-fg">{p.destination}</td>
                    <td className={PROTOCOL_COLORS[p.colorHint]}>{p.protocol}</td>
                    <td>{p.length}</td>
                    <td className="text-fg-dim">{p.info}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : tab === "conversations" ? (
            <EmptyState title="Conversations" detail="Endpoint and conversation matrices arrive with the dissection engine (arc 2)." badge="packet studio" />
          ) : tab === "statistics" ? (
            <EmptyState title="Statistics" detail="Protocol hierarchy, I/O graphs and expert information arrive in arc 2." badge="packet studio" />
          ) : (
            <EmptyState title="Follow stream" detail="TCP/UDP/HTTP stream reassembly with provenance extraction lands arc 2." badge="packet studio" />
          )}
        </div>

        <div className="flex min-h-0 flex-[3] flex-col overflow-hidden border-b border-line bg-panel">
          <div className="flex h-7 shrink-0 items-center border-b border-line bg-sidebar px-2 text-[10px] font-medium uppercase tracking-wider text-fg-muted">
            Packet details: {packet ? `frame ${packet.no}` : "no selection"}
          </div>
          <div className="min-h-0 flex-1 overflow-auto p-1">
            {packet ? detailTree(packet).map((node, i) => <DetailBranch key={i} node={node} depth={0} />) : null}
          </div>
        </div>

        <div className="flex min-h-0 flex-[3] flex-col overflow-hidden bg-panel">
          <div className="flex h-7 shrink-0 items-center border-b border-line bg-sidebar px-2 text-[10px] font-medium uppercase tracking-wider text-fg-muted">
            Packet bytes (offset · hex · ascii)
          </div>
          <div className="min-h-0 flex-1 overflow-auto">
            <pre className="p-1 font-mono text-[11px] leading-relaxed text-fg-dim">
              {rows.map((row) => (
                <div key={row.offset}>
                  <span className="text-fg-muted">{row.offset.toString(16).padStart(4, "0")}</span>
                  {"  "}
                  {row.hex}
                  {"  "}
                  <span className="text-blue">{row.ascii}</span>
                </div>
              ))}
            </pre>
          </div>
        </div>
      </div>

      <div className="flex h-7 shrink-0 items-center gap-1 border-t border-line bg-sidebar px-2">
        {(["packets", "conversations", "statistics", "streams"] as const).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={`h-5 border px-2 font-mono text-[10px] uppercase tracking-wide ${
              tab === t ? "border-blue/50 text-blue" : "border-transparent text-fg-muted hover:text-fg"
            }`}
          >
            {t}
          </button>
        ))}
        <span className="ml-auto font-mono text-[10px] text-fg-muted">{packets.length} packets · sample capture · engine: arc 2</span>
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
            <ToolButton disabled title="Scope configuration, engine integration arc 2">Configure scope</ToolButton>
            <ToolButton disabled title="Ettercap capability vetting arc 2">Enable lab mode</ToolButton>
            <Chip>arc 2</Chip>
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
            { value: "web", label: "Web review (engine: arc 3)" },
            { value: "templates", label: "Template checks (engine: arc 3)" },
          ]}
          ariaLabel="Scan profile"
        />
        <ToolButton tone="primary" onClick={wb.runDemoJob} title="Runs the shared job pipeline demo; scan engines arrive arc 3">
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
            <div className="mt-1">raw engine output, scan diff and export land arc 3;</div>
            <div>every finding keeps engine id/version and policy in</div>
            <div>provenance (Master Plan §5.3).</div>
          </div>
        </Pane>
      </div>
    </div>
  );
}

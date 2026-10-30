"use client";
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

// ---------------------------------------------------------------- scanning ---

export function ScanView() {
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

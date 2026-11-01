"use client";
import { useEffect, useMemo, useState } from "react";
import { ChevronRight, FolderOpen, Play, ShieldAlert, Square } from "lucide-react";
import { Chip, EmptyState, Pane, Select, TextInput, ToolButton } from "@ds/panes";
import { hexDump } from "@lib/hex";
import { isDesktop, pcapOpenDialog, pcapPacketBytes, type HexResponseWire, type PcapOpenWire, type PcapPacketWire } from "@lib/ipc";
import { useWorkbench } from "@state/workbench";
import type { ToolId } from "@state/tool-registry";
import {
  PROTOCOL_COLORS,
  SAMPLE_HOSTS,
  SAMPLE_PACKETS,
  detailTree,
  sampleFrameBytes,
  type DetailNode,
} from "./model";

// ------------------------------------------------------------ network lab ---

export function NetworkLabView() {
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


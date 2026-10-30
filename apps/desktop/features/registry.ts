/**
 * Feature registry — the single source of truth for the category rail and the
 * navigator (Master Plan §3.4). Tools are named by user-facing operation, never
 * by upstream engine: engines appear only in results provenance (§5.5, §6).
 */
import type { LucideIcon } from "lucide-react";
import { FileSearch, Globe, KeyRound, Microscope, Network } from "lucide-react";

export type CategoryId = "crypto" | "network" | "web" | "reverse" | "forensics";

export type ToolId =
  | "crypto.recipes"
  | "crypto.hash"
  | "crypto.ops"
  | "network.packet"
  | "network.lab"
  | "network.scan"
  | "web.proxy"
  | "web.history"
  | "web.repeater"
  | "web.scanner"
  | "reverse.workbench"
  | "forensics.files"
  | "forensics.metadata"
  | "forensics.strings";

export interface ToolDescriptor {
  id: ToolId;
  category: CategoryId;
  label: string;
  hint: string;
  disabled?: boolean;
  disabledReason?: string;
}

export interface CategoryDescriptor {
  id: CategoryId;
  label: string;
  icon: LucideIcon;
  tools: ToolDescriptor[];
}

export const CATEGORIES: CategoryDescriptor[] = [
  {
    id: "crypto",
    label: "Crypto",
    icon: KeyRound,
    tools: [
      {
        id: "crypto.recipes",
        category: "crypto",
        label: "Recipes",
        hint: "Visual transformation pipeline (CyberChef-style four-column workflow)",
      },
      {
        id: "crypto.hash",
        category: "crypto",
        label: "Hash Analysis",
        hint: "Identify, verify, benchmark and run authorized recovery sessions — engine planner picks CPU/GPU implementation",
      },
      {
        id: "crypto.ops",
        category: "crypto",
        label: "Crypto Ops",
        hint: "Generate hashes, HMACs and key material with explicit algorithm parameters",
      },
    ],
  },
  {
    id: "network",
    label: "Network",
    icon: Network,
    tools: [
      {
        id: "network.packet",
        category: "network",
        label: "Packet Analysis",
        hint: "Offline capture inspection: packet list, protocol details, bytes (Wireshark-style three-pane layout)",
      },
      {
        id: "network.lab",
        category: "network",
        label: "Network Lab",
        hint: "Authorized-scope active network mode (Ettercap-inspired) — gated, labeled, never mixed into passive evidence",
      },
      {
        id: "network.scan",
        category: "network",
        label: "Scanning",
        hint: "Target + profile + results: host/port discovery and assessment engines behind one job model (Zenmap-style)",
      },
    ],
  },
  {
    id: "web",
    label: "Web",
    icon: Globe,
    tools: [
      { id: "web.proxy", category: "web", label: "Proxy", hint: "HTTP/S interception with user-controlled local listener" },
      { id: "web.history", category: "web", label: "History", hint: "Full proxy history with filters and evidence links" },
      { id: "web.repeater", category: "web", label: "Repeater", hint: "Request replay and response comparison" },
      { id: "web.scanner", category: "web", label: "Scanner", hint: "Crawl and active scan with findings provenance" },
    ],
  },
  {
    id: "reverse",
    label: "Reverse",
    icon: Microscope,
    tools: [
      {
        id: "reverse.workbench",
        category: "reverse",
        label: "Workbench",
        hint: "Decompiler-centric analysis",
        disabled: true,
        disabledReason: "Phase 6",
      },
    ],
  },
  {
    id: "forensics",
    label: "Forensics",
    icon: FileSearch,
    tools: [
      { id: "forensics.files", category: "forensics", label: "File Analysis", hint: "Evidence tree, hex, signatures, extraction with path safety" },
      { id: "forensics.metadata", category: "forensics", label: "Metadata", hint: "Exif-compatible metadata inspection" },
      { id: "forensics.strings", category: "forensics", label: "Strings & Entropy", hint: "String extraction and entropy profiling across evidence" },
    ],
  },
];

export function toolById(id: ToolId): ToolDescriptor | undefined {
  for (const category of CATEGORIES) {
    const tool = category.tools.find((t) => t.id === id);
    if (tool) return tool;
  }
  return undefined;
}

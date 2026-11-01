"use client";

import { FolderOpen, History } from "lucide-react";
import { Button } from "@/components/ui/button";

/** Compact workbench entry. Files and real interfaces open the same analyzer. */
export function PacketStartView({ opening, desktop, onOpen, lastOpened, onResumeOpened }: {
  opening: boolean;
  desktop: boolean;
  onOpen: () => void;
  lastOpened: string | null;
  onResumeOpened: () => void;
}) {
  return (
    <div className="w-full shrink-0 px-5 pt-5 sm:px-7 sm:pt-7">
      <header className="mb-6 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h1 className="text-lg font-semibold tracking-tight">Packet Analysis</h1>
        <span className="text-xs text-fg-muted">Capture · Inspect · Investigate</span>
      </header>
      <section aria-labelledby="open-capture-title">
        <h2 id="open-capture-title" className="mb-2 text-sm font-medium text-fg-dim">Open</h2>
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="secondary" disabled={!desktop || opening} onClick={onOpen}
            title={desktop ? "Open PCAP or PCAPNG" : "Available in the desktop application"}>
            <FolderOpen size={15} /> {opening ? "Opening…" : "Capture file"}
          </Button>
        </div>
      </section>
      <section aria-labelledby="recent-captures-title" className="mt-6">
        <h2 id="recent-captures-title" className="mb-2 flex items-center gap-2 text-sm font-medium text-fg-dim">
          <History size={14} aria-hidden="true" /> Recent
        </h2>
        {lastOpened ? (
          <div className="flex max-w-xl items-center gap-2">
            <span className="min-w-0 truncate font-mono text-xs text-fg-dim" title={lastOpened}>{lastOpened}</span>
            <Button variant="outline" size="xs" onClick={onResumeOpened}>Resume</Button>
          </div>
        ) : <p className="text-xs text-fg-muted">No recent captures</p>}
      </section>
    </div>
  );
}

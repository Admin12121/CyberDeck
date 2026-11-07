"use client";

import { FolderOpen, History, Radar } from "lucide-react";
import { Button } from "@/components/ui/button";
import { EmptyCard } from "@ds/compact";

/** Compact workbench entry. Files and real interfaces open the same analyzer. */
export function PacketStartView({ opening, desktop, onOpen, lastOpened, onResumeOpened }: {
  opening: boolean;
  desktop: boolean;
  onOpen: () => void;
  lastOpened: string | null;
  onResumeOpened: () => void;
}) {
  return (
    <EmptyCard
      icon={Radar}
      title="Packet Analysis"
      footer={
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="secondary" disabled={!desktop || opening} onClick={onOpen}
            title={desktop ? "Open PCAP or PCAPNG" : "Available in the desktop application"}>
            <FolderOpen size={15} /> {opening ? "Opening…" : "Capture file"}
          </Button>
          {lastOpened ? (
            <Button variant="outline" size="xs" onClick={onResumeOpened}>Resume</Button>
          ) : null}
        </div>
      }
    >
      <p>Capture · Inspect · Investigate</p>
      <section aria-labelledby="recent-captures-title" className="mt-4">
        <h2 id="recent-captures-title" className="mb-1 flex items-center gap-2 font-medium text-fg">
          <History size={14} aria-hidden="true" /> Recent
        </h2>
        {lastOpened ? (
          <span className="block truncate font-mono text-fg-dim" title={lastOpened}>{lastOpened}</span>
        ) : <p>No recent captures</p>}
      </section>
    </EmptyCard>
  );
}

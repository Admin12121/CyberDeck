"use client";
/** Thin dispatcher: all network tools stay mounted; hidden views keep state. */
import { CategoryWorkspace } from "@ds/compact";
import { PacketStudioView } from "./PacketStudioView";
import { NetworkLabView } from "./NetworkLabView";
import { ScanView } from "./ScanView";
import { ScanInsightsView } from "./ScanInsightsView";
import type { ToolId } from "@state/tool-registry";

export function NetworkWorkspace({ tool }: { tool: ToolId }) {
  return (
    <div className="flex h-full min-h-0 flex-col">
      <CategoryWorkspace
        activeId={tool}
        views={[
          { id: "network.packet", render: () => <PacketStudioView /> },
          { id: "network.lab", render: () => <NetworkLabView /> },
          { id: "network.scan", render: () => <ScanView /> },
          { id: "network.insights", render: () => <ScanInsightsView /> },
        ]}
      />
    </div>
  );
}

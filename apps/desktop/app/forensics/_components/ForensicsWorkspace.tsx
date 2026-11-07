"use client";
/** Thin dispatcher: all forensics tools stay mounted; hidden views keep state. */
import { CategoryWorkspace } from "@ds/compact";
import { FileAnalysisView } from "./FileAnalysisView";
import { CaseFindingsView } from "./CaseFindingsView";
import { MetadataView } from "./MetadataView";
import { StringsView } from "./StringsView";
import { EvidenceProvider } from "./shared";
import type { ToolId } from "@state/tool-registry";
import { useWorkbench } from "@state/workbench";

export function ForensicsWorkspace({ tool }: { tool: ToolId }) {
  const { caseId } = useWorkbench();
  return (
    <EvidenceProvider key={caseId}>
      <div className="flex h-full min-h-0 flex-col">
        <CategoryWorkspace
          activeId={tool}
          views={[
            { id: "forensics.findings", render: () => <CaseFindingsView /> },
            { id: "forensics.files", render: (active) => <FileAnalysisView active={active} /> },
            { id: "forensics.metadata", render: (active) => <MetadataView active={active} /> },
            { id: "forensics.strings", render: () => <StringsView /> },
          ]}
        />
      </div>
    </EvidenceProvider>
  );
}

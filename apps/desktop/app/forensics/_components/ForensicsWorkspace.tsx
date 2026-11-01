"use client";
/** Thin dispatcher: all forensics tools stay mounted; hidden views keep state. */
import { FileAnalysisView } from "./FileAnalysisView";
import { CaseFindingsView } from "./CaseFindingsView";
import { MetadataView } from "./MetadataView";
import { StringsView } from "./StringsView";
import { EvidenceProvider } from "./shared";
import type { ToolId } from "@state/tool-registry";
import { useWorkbench } from "@state/workbench";

export function ForensicsWorkspace({ tool }: { tool: ToolId }) {
  const { caseId } = useWorkbench();
  const show = (id: ToolId) => (tool === id ? "h-full" : "hidden h-full");
  return (
    <EvidenceProvider key={caseId}><div className="flex h-full min-h-0 flex-col">
      <div className="min-h-0 flex-1">

      <div className={show("forensics.findings")}><CaseFindingsView /></div>
      <div className={show("forensics.files")}><FileAnalysisView active={tool === "forensics.files"} /></div>
      <div className={show("forensics.metadata")}><MetadataView active={tool === "forensics.metadata"} /></div>
      <div className={show("forensics.strings")}><StringsView /></div>
      </div>
    </div></EvidenceProvider>
  );
}
"use client";
/** Thin dispatcher: all forensics tools stay mounted; hidden views keep state. */
import { FileAnalysisView } from "./FileAnalysisView";
import { CaseFindingsView } from "./CaseFindingsView";
import { MetadataView } from "./MetadataView";
import { StringsView } from "./StringsView";
import { ToolTabs } from "@shell/ToolTabs";
import { EvidenceProvider } from "./shared";
import type { ToolId } from "@features/registry";

export function ForensicsWorkspace({ tool }: { tool: ToolId }) {
  const show = (id: ToolId) => (tool === id ? "h-full" : "hidden h-full");
  return (
    <EvidenceProvider><div className="flex h-full min-h-0 flex-col">
      <ToolTabs category="forensics" active={tool} />
      <div className="min-h-0 flex-1">

      <div className={show("forensics.findings")}><CaseFindingsView /></div>
      <div className={show("forensics.files")}><FileAnalysisView active={tool === "forensics.files"} /></div>
      <div className={show("forensics.metadata")}><MetadataView active={tool === "forensics.metadata"} /></div>
      <div className={show("forensics.strings")}><StringsView /></div>
      </div>
    </div></EvidenceProvider>
  );
}
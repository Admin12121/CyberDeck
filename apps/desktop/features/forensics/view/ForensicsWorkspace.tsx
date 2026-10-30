"use client";
/** Thin dispatcher: all forensics tools stay mounted; hidden views keep state. */
import { FileAnalysisView } from "./FileAnalysisView";
import { MetadataView } from "./MetadataView";
import { StringsView } from "./StringsView";
import type { ToolId } from "@features/registry";

export function ForensicsWorkspace({ tool }: { tool: ToolId }) {
  const show = (id: ToolId) => (tool === id ? "h-full" : "hidden h-full");
  return (
    <>
      <div className={show("forensics.files")}><FileAnalysisView /></div>
      <div className={show("forensics.metadata")}><MetadataView /></div>
      <div className={show("forensics.strings")}><StringsView /></div>
    </>
  );
}

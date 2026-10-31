"use client";
/** Thin dispatcher: all crypto tools stay mounted; hidden views keep state. */
import { HashAnalysisView } from "./HashAnalysisView";
import { RecipesView } from "./RecipesView";
import { CryptoOpsView } from "./CryptoOpsView";
import { ToolTabs } from "@shell/ToolTabs";
import type { ToolId } from "@features/registry";

export function CryptoWorkspace({ tool }: { tool: ToolId }) {
  const show = (id: ToolId) => (tool === id ? "h-full" : "hidden h-full");
  return (
    <div className="flex h-full min-h-0 flex-col">
      <ToolTabs category="crypto" active={tool} />
      <div className="min-h-0 flex-1">

      <div className={show("crypto.recipes")}><RecipesView /></div>
      <div className={show("crypto.hash")}><HashAnalysisView /></div>
      <div className={show("crypto.ops")}><CryptoOpsView /></div>
      </div>
    </div>
  );
}
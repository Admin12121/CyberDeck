"use client";
/** Thin dispatcher: all crypto tools stay mounted; hidden views keep state. */
import { CategoryWorkspace } from "@ds/compact";
import { HashAnalysisView } from "./HashAnalysisView";
import { RecipesView } from "./RecipesView";
import { CryptoOpsView } from "./CryptoOpsView";
import type { ToolId } from "@state/tool-registry";

export function CryptoWorkspace({ tool }: { tool: ToolId }) {
  return (
    <div className="flex h-full min-h-0 flex-col">
      <CategoryWorkspace
        activeId={tool}
        views={[
          { id: "crypto.recipes", render: () => <RecipesView /> },
          { id: "crypto.hash", render: () => <HashAnalysisView /> },
          { id: "crypto.ops", render: () => <CryptoOpsView /> },
        ]}
      />
    </div>
  );
}

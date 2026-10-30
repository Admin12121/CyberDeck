"use client";
/**
 * Reverse feature placeholder for Phase 6 (Master Plan §5.7).
 * The decompiler-centric multi-pane layout is deliberately NOT built here;
 * this screen records the decision and links the future RFC so the category
 * rail can still show the reserved workspace.
 */
import { EmptyState, Pane } from "@ds/panes";

export function ReverseWorkspace() {
  return (
    <div className="flex h-full min-h-0 gap-px bg-line">
      <Pane title="Modules / symbols" className="w-64 shrink-0">
        <EmptyState title="Reserved (Phase 6)" detail="Full decompiler workspace: functions tree, symbols, segments." badge="future" />
      </Pane>
      <div className="flex min-w-0 flex-1 flex-col gap-px">
        <Pane title="Decompiler / assembly / hex" className="min-h-0 flex-1">
          <EmptyState
            title="Reverse Engineering Studio ships in a later release"
            detail="PE/ELF/Mach-O analysis, xrefs, CFG/call graphs and decompilation are scoped as a dedicated phase (§5.7, RFC-006). Core workbench, rendering model and analysis storage are proven first."
            badge="phase 6"
          />
        </Pane>
      </div>
      <Pane title="Xrefs / types" className="w-64 shrink-0">
        <EmptyState title="Reserved" badge="phase 6" />
      </Pane>
    </div>
  );
}

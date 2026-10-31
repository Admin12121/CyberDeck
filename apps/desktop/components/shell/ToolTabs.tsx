"use client";
/** Tool tab bar rendered at the top of multi-tool category workspaces. */
import { CATEGORIES, type CategoryId, type ToolId } from "@features/registry";
import { useWorkbench } from "@state/workbench";

export function ToolTabs({ category, active }: { category: CategoryId; active: ToolId }) {
  const wb = useWorkbench();
  const cat = CATEGORIES.find((c) => c.id === category);
  if (!cat || cat.tools.length <= 1) return null;
  return (
    <div className="flex h-8 shrink-0 items-center gap-1 border-b border-line bg-sidebar px-2">
      {cat.tools.map((tool) => (
        <button
          key={tool.id}
          type="button"
          title={tool.hint}
          onClick={() => wb.selectTool(tool.id)}
          className={`h-6 border px-3 font-mono text-[10px] uppercase tracking-wide ${
            active === tool.id
              ? "border-orange/50 text-orange"
              : "border-transparent text-fg-muted hover:text-fg"
          }`}
        >
          {tool.label}
        </button>
      ))}
    </div>
  );
}

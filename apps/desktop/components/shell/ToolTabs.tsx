"use client";
/** Tool tab bar rendered at the top of multi-tool category workspaces. */
import { CATEGORIES, type CategoryId, type ToolId } from "@features/registry";
import { useWorkbench } from "@state/workbench";

export function ToolTabs({ category, active }: { category: CategoryId; active: ToolId }) {
  const wb = useWorkbench();
  const cat = CATEGORIES.find((c) => c.id === category);
  if (!cat || cat.tools.filter((tool) => !tool.disabled).length <= 1) return null;
  const sidebarIsPrimary = wb.category === category && wb.navigatorOpen;
  return (
    <nav aria-label={`${cat.label} tools`} className={`${sidebarIsPrimary ? "min-[1080px]:hidden " : ""}flex h-9 shrink-0 items-center gap-1 overflow-x-auto border-b border-line bg-sidebar px-2`}>
      {cat.tools.map((tool) => (
        <button
          key={tool.id}
          type="button"
          title={tool.disabled ? tool.disabledReason : tool.hint}
          aria-current={active === tool.id ? "page" : undefined}
          disabled={tool.disabled}
          onClick={() => wb.selectTool(tool.id)}
          className={`h-8 shrink-0 border-b px-3 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
            active === tool.id
              ? "border-fg bg-selected/60 text-fg"
              : "border-transparent text-fg-muted hover:bg-raised hover:text-fg"
          }`}
        >
          {tool.label}
        </button>
      ))}
    </nav>
  );
}

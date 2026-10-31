"use client";
/** Section navigator: category label, tool list, and user-controlled width. */
import { CATEGORIES, toolById } from "@features/registry";
import { useWorkbench } from "@state/workbench";

export function Navigator() {
  const wb = useWorkbench();
  const category = CATEGORIES.find((c) => c.id === wb.category);
  if (!category) return null;

  return (
    <aside
      className="flex shrink-0 flex-col bg-sidebar"
      style={{ width: wb.navigatorWidth }}
      aria-label="Tools"
    >
      <div className="flex h-8 shrink-0 items-center border-b border-line px-3 text-[10px] font-medium uppercase tracking-wider text-fg-muted">
        {category.label}
      </div>
      <div className="flex-1 overflow-auto p-1">
        {category.tools.map((tool) => {
          const active = wb.tool === tool.id;
          return (
            <button
              key={tool.id}
              type="button"
              title={tool.disabled ? `${tool.label} (${tool.disabledReason ?? "unavailable"})` : tool.hint}
              disabled={tool.disabled}
              onClick={() => wb.selectTool(tool.id)}
              className={`mb-px block w-full truncate px-2 py-1.5 text-left text-xs ${
                tool.disabled
                  ? "cursor-not-allowed text-fg-muted opacity-50"
                  : active
                    ? "bg-orange-dim text-fg"
                    : "text-fg-dim hover:bg-raised hover:text-fg"
              }`}
            >
              {tool.label}
              {tool.disabled ? ` (${tool.disabledReason ?? "soon"})` : ""}
            </button>
          );
        })}
      </div>
    </aside>
  );
}

export function activeToolLabel(toolId: string): string {
  return toolById(toolId as never)?.label ?? toolId;
}
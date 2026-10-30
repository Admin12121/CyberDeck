"use client";
/** Section navigator — category label + tool list with disabled reasons. */
import { toolById, CATEGORIES } from "@features/registry";
import { useWorkbench } from "@state/workbench";

export function Navigator() {
  const wb = useWorkbench();
  const category = CATEGORIES.find((c) => c.id === wb.category);
  if (!category) return null;

  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-line bg-sidebar" aria-label="Tools">
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
              title={tool.disabled ? `${tool.label} — ${tool.disabledReason ?? "unavailable"}` : tool.hint}
              disabled={tool.disabled}
              onClick={() => wb.selectTool(tool.id)}
              className={`mb-px block w-full truncate border-l-2 px-2 py-1.5 text-left text-xs ${
                tool.disabled
                  ? "cursor-not-allowed border-transparent text-fg-muted opacity-50"
                  : active
                    ? "border-blue bg-selected text-fg"
                    : "border-transparent text-fg-dim hover:bg-raised hover:text-fg"
              }`}
            >
              {tool.label}
              {tool.disabled ? ` (${tool.disabledReason ?? "soon"})` : ""}
            </button>
          );
        })}
      </div>
      <div className="shrink-0 border-t border-line p-2">
        <button
          type="button"
          onClick={() => wb.setPaletteOpen(true)}
          className="flex w-full items-center justify-between border border-line px-2 py-1 font-mono text-[10px] text-fg-muted hover:border-line-strong hover:text-fg"
        >
          search tools…
          <kbd className="border border-line px-1">Ctrl K</kbd>
        </button>
      </div>
    </aside>
  );
}

export function activeToolLabel(toolId: string): string {
  return toolById(toolId as never)?.label ?? toolId;
}

"use client";

import { CATEGORIES } from "@features/registry";
import { useWorkbench } from "@state/workbench";

export function ContextNavigator() {
  const wb = useWorkbench();
  const category = CATEGORIES.find((item) => item.id === wb.category);

  return (
    <aside
      id="cyberdeck-context-navigator"
      aria-label={`${category?.label ?? "Workspace"} tools`}
      className="flex min-h-0 shrink-0 flex-col border-r border-line bg-sidebar min-[1080px]:border-r-0"
      style={{ width: wb.navigatorWidth }}
    >
      <div className="cd-workspace-toolbar px-3">
        <h2 className="truncate text-sm font-semibold text-fg">{category?.label}</h2>
      </div>
      <nav aria-label={`${category?.label ?? "Workspace"} navigation`}
        className="min-h-0 flex-1 overflow-y-auto px-2 py-1">
        {category?.tools.map((tool) => {
          const active = tool.id === wb.tool;
          return (
            <button key={tool.id} type="button" disabled={tool.disabled}
              onClick={() => wb.selectTool(tool.id)}
              title={tool.disabled ? tool.disabledReason : tool.hint}
              aria-current={active ? "page" : undefined}
              className={`mb-0.5 flex min-h-9 w-full items-center rounded-md px-3 py-2 text-left text-[13px] transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${active ? "bg-selected font-medium text-fg" : "text-fg-muted hover:bg-raised hover:text-fg"}`}>
              <span className="truncate">{tool.label}</span>
            </button>
          );
        })}
      </nav>
    </aside>
  );
}

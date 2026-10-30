"use client";
/** Global category rail: fixed icons, tooltips via title (§3.4). */
import { CATEGORIES } from "@features/registry";
import { useWorkbench } from "@state/workbench";

export function Rail() {
  const wb = useWorkbench();
  return (
    <nav className="flex w-12 shrink-0 flex-col items-center gap-1 border-r border-line bg-sidebar py-2" aria-label="Categories">
      {CATEGORIES.map((category) => {
        const Icon = category.icon;
        const active = wb.category === category.id;
        return (
          <button
            key={category.id}
            type="button"
            title={category.label}
            aria-label={category.label}
            aria-current={active ? "page" : undefined}
            onClick={() => wb.selectCategory(category.id)}
            className={`relative flex h-9 w-9 items-center justify-center ${
              active ? "text-blue" : "text-fg-muted hover:text-fg"
            }`}
          >
            {active ? <span className="absolute left-0 top-1/2 h-5 w-0.5 -translate-y-1/2 bg-blue" /> : null}
            <Icon size={18} strokeWidth={1.5} />
          </button>
        );
      })}
    </nav>
  );
}

"use client";
/** Logo + category rail; the command button lives at the bottom. */
import { Command } from "lucide-react";
import { CATEGORIES } from "@features/registry";
import { useWorkbench } from "@state/workbench";

export function Rail() {
  const wb = useWorkbench();
  return (
    <nav className="flex w-12 shrink-0 flex-col items-center border-r border-line bg-sidebar" aria-label="Categories">
      <div className="flex h-8 w-full shrink-0 items-center justify-center border-b border-line">
        <img src="/logo.webp" alt="HackTool" className="h-5 w-5" />
      </div>
      <div className="flex w-full flex-1 flex-col items-center gap-1 py-2">
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
                active ? "text-orange" : "text-fg-muted hover:text-fg"
              }`}
            >
              <Icon size={18} strokeWidth={active ? 2 : 1.5} />
            </button>
          );
        })}
      </div>
      <button
        type="button"
        title="Commands (Ctrl K)"
        aria-label="Commands"
        onClick={() => wb.setPaletteOpen(true)}
        className="flex h-9 w-9 items-center justify-center text-fg-muted hover:text-fg"
      >
        <Command size={16} strokeWidth={1.5} />
      </button>
    </nav>
  );
}

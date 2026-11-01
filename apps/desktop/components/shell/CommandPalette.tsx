"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowDown, ArrowUp, CornerDownLeft, Search, X } from "lucide-react";
import { CATEGORIES } from "@features/registry";
import { useWorkbench } from "@state/workbench";

type PaletteAction = { id: string; label: string; hint: string; shortcut?: string; run: () => void };
type PaletteGroup = { label: string; items: PaletteAction[] };

export function CommandPalette() {
  const wb = useWorkbench();
  const dialog = useRef<HTMLDialogElement>(null);
  const search = useRef<HTMLInputElement>(null);
  const previousFocus = useRef<HTMLElement | null>(null);
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);

  const groups = useMemo<PaletteGroup[]>(() => [
    ...CATEGORIES.map((category) => ({
      label: category.label,
      items: category.tools.filter((tool) => !tool.disabled).map((tool) => ({
        id: tool.id, label: tool.label, hint: tool.hint, run: () => wb.selectTool(tool.id),
      })),
    })).filter((group) => group.items.length > 0),
    {
      label: "Actions",
      items: [
        { id: "jobs", label: "Open jobs dock", hint: "See active and completed jobs", shortcut: "Ctrl J", run: () => { wb.setDockTab("jobs"); wb.setDockOpen(true); } },
        { id: "console", label: "Open console", hint: "Inspect local operation messages", shortcut: "Ctrl `", run: () => { wb.setDockTab("console"); wb.setDockOpen(true); } },
        { id: "navigator", label: "Toggle navigator", hint: "Expand or collapse contextual navigation", shortcut: "Ctrl B", run: wb.toggleNavigator },
      ],
    },
  ], [wb]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return groups.map((group) => ({
      ...group,
      items: needle ? group.items.filter((item) => `${item.label} ${item.hint} ${group.label}`.toLocaleLowerCase().includes(needle)) : group.items,
    })).filter((group) => group.items.length > 0);
  }, [groups, query]);

  const items = filtered.flatMap((group) => group.items);

  useEffect(() => {
    const node = dialog.current;
    if (!node) return;
    if (wb.paletteOpen) {
      if (!node.open) {
        previousFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
        node.showModal();
        setQuery("");
        setActiveIndex(0);
      }
      search.current?.focus();
    } else if (node.open) {
      node.close();
    }
  }, [wb.paletteOpen]);

  useEffect(() => {
    if (!wb.paletteOpen) return;
    const id = items[Math.min(activeIndex, items.length - 1)]?.id;
    if (id) document.getElementById(`cyberdeck-command-${id}`)?.scrollIntoView({ block: "nearest" });
  }, [activeIndex, items, wb.paletteOpen]);

  function run(action: PaletteAction) {
    wb.setPaletteOpen(false);
    action.run();
  }

  return (
    <dialog
      ref={dialog}
      aria-label="Command palette"
      onCancel={() => wb.setPaletteOpen(false)}
      onClose={() => { wb.setPaletteOpen(false); previousFocus.current?.focus(); }}
      onClick={(event) => { if (event.target === dialog.current) wb.setPaletteOpen(false); }}
      className="fixed top-[10vh] mx-auto max-h-[min(560px,80vh)] w-[min(560px,calc(100vw-32px))] overflow-hidden rounded-2xl border border-line bg-popover p-0 text-popover-foreground shadow-2xl backdrop:bg-black/55 backdrop:backdrop-blur-[2px]"
    >
      <div className="flex min-h-0 flex-col">
        <div className="flex h-14 items-center gap-3 border-b border-line px-4">
          <Search size={19} className="shrink-0 text-fg-muted" aria-hidden="true" />
          <input
            ref={search}
            value={query}
            onChange={(event) => { setQuery(event.target.value); setActiveIndex(0); }}
            onKeyDown={(event) => {
              if (event.key === "ArrowDown" || event.key === "ArrowUp") {
                event.preventDefault();
                setActiveIndex((index) => Math.max(0, Math.min(items.length - 1, index + (event.key === "ArrowDown" ? 1 : -1))));
              } else if (event.key === "Enter" && items[activeIndex]) {
                event.preventDefault();
                run(items[activeIndex]);
              } else if (event.key === "Escape") {
                event.preventDefault();
                wb.setPaletteOpen(false);
              }
            }}
            role="combobox"
            aria-label="Search tools and commands"
            aria-autocomplete="list"
            aria-expanded={wb.paletteOpen}
            aria-controls="cyberdeck-command-results"
            aria-activedescendant={items[activeIndex] ? `cyberdeck-command-${items[activeIndex].id}` : undefined}
            placeholder="Search tools and commands…"
            className="h-12 min-w-0 flex-1 bg-transparent text-sm text-fg outline-none placeholder:text-fg-muted"
          />
          <button type="button" aria-label="Close command palette" onClick={() => wb.setPaletteOpen(false)}
            className="flex size-8 shrink-0 items-center justify-center rounded-lg text-fg-muted hover:bg-accent hover:text-fg">
            <X size={17} aria-hidden="true" />
          </button>
        </div>
        <div id="cyberdeck-command-results" role="listbox" aria-label="Available commands" className="min-h-0 max-h-[min(420px,60vh)] overflow-y-auto p-2">
          {items.length === 0 ? <p role="status" className="px-4 py-10 text-center text-sm text-fg-muted">No matching CyberDeck commands.</p> : null}
          {filtered.map((group) => (
            <div key={group.label} role="group" aria-label={group.label} className="pb-1">
              <div className="px-3 py-2 text-xs font-semibold uppercase tracking-wide text-fg-muted">{group.label}</div>
              {group.items.map((item) => {
                const index = items.findIndex((entry) => entry.id === item.id);
                const selected = activeIndex === index;
                return (
                  <div
                    key={item.id}
                    id={`cyberdeck-command-${item.id}`}
                    role="option"
                    aria-selected={selected}
                    onMouseEnter={() => setActiveIndex(index)}
                    onClick={() => run(item)}
                    className={`flex min-h-11 cursor-pointer items-center gap-3 rounded-lg px-3 py-2 transition-colors ${selected ? "bg-accent text-accent-foreground" : "text-fg hover:bg-accent"}`}
                  >
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-medium">{item.label}</div>
                      <div className="truncate text-xs text-fg-muted">{item.hint}</div>
                    </div>
                    {item.shortcut ? <kbd className="shrink-0 rounded border border-line px-2 py-0.5 font-mono text-xs text-fg-muted">{item.shortcut}</kbd> : null}
                  </div>
                );
              })}
            </div>
          ))}
        </div>
        <footer className="flex flex-wrap items-center justify-between gap-3 border-t border-line bg-sidebar px-4 py-3 text-xs text-fg-muted">
          <span className="flex items-center gap-2"><kbd className="flex items-center rounded border border-line px-1 py-0.5"><ArrowUp size={13}/><ArrowDown size={13}/></kbd> Navigate <kbd className="ml-2 rounded border border-line p-1"><CornerDownLeft size={13}/></kbd> Open</span>
          <span><kbd className="rounded border border-line px-2 py-1">Esc</kbd> Close</span>
        </footer>
      </div>
    </dialog>
  );
}

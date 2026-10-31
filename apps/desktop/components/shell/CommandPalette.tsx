"use client";
/** Command palette (Ctrl/Cmd+K): searchable tools and actions (§3.5). */
import { useMemo, useState } from "react";
import { CATEGORIES, toolById } from "@features/registry";
import { useWorkbench } from "@state/workbench";

interface Command {
  id: string;
  label: string;
  hint: string;
  run: () => void;
}

export function CommandPalette() {
  const wb = useWorkbench();
  const [query, setQuery] = useState("");

  const commands = useMemo<Command[]>(() => {
    const toolCommands: Command[] = CATEGORIES.flatMap((category) =>
      category.tools
        .filter((tool) => !tool.disabled)
        .map((tool) => ({
          id: tool.id,
          label: `Go to ${category.label} / ${tool.label}`,
          hint: tool.hint,
          run: () => wb.selectTool(tool.id),
        })),
    );
    const actions: Command[] = [
      { id: "action.job", label: "Run demo job", hint: "Queue a cancellable job through the shared pipeline", run: wb.runDemoJob },
      { id: "action.dock", label: "Toggle jobs dock", hint: "Ctrl+J", run: wb.toggleDock },
    ];
    return [...toolCommands, ...actions];
  }, [wb]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter((c) => c.label.toLowerCase().includes(q) || c.hint.toLowerCase().includes(q));
  }, [commands, query]);

  if (!wb.paletteOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 pt-[12vh]" role="dialog" aria-label="Command palette" onClick={() => wb.setPaletteOpen(false)}>
      <div className="w-[560px] max-w-[90vw] border border-line-strong bg-panel shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="border-b border-line p-2">
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && filtered[0]) {
                filtered[0].run();
                wb.setPaletteOpen(false);
              }
            }}
            placeholder="search commands and tools…"
            aria-label="Command search"
            className="h-8 w-full bg-app px-2 font-mono text-xs text-fg placeholder:text-fg-muted focus:outline-none"
          />
        </div>
        <ul className="max-h-80 overflow-auto p-1">
          {filtered.length === 0 ? (
            <li className="p-3 font-mono text-[11px] text-fg-muted">no matching commands</li>
          ) : (
            filtered.map((command, index) => (
              <li key={command.id}>
                <button
                  type="button"
                  onClick={() => {
                    command.run();
                    wb.setPaletteOpen(false);
                  }}
                  className={`block w-full px-2 py-1.5 text-left ${index === 0 ? "bg-orange-dim" : "hover:bg-raised"}`}
                >
                  <div className="text-xs text-fg">{command.label}</div>
                  <div className="truncate font-mono text-[10px] text-fg-muted">{command.hint}</div>
                </button>
              </li>
            ))
          )}
        </ul>
        <div className="flex items-center justify-between border-t border-line px-2 py-1 font-mono text-[10px] text-fg-muted">
          <span>↑↓ browse · ↵ run · esc close</span>
          <span>{filtered.length} commands</span>
        </div>
      </div>
    </div>
  );
}

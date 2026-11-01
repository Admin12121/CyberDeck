"use client";

import { useEffect, useState } from "react";
import { Command, ListTodo, Moon, PanelLeftOpen, PanelLeftClose, Sun } from "lucide-react";
import { CATEGORIES } from "@features/registry";
import { useWorkbench } from "@state/workbench";

export function Rail() {
  const wb = useWorkbench();
  const [dark, setDark] = useState(true);
  const running = Object.values(wb.jobs).filter((job) => job.status === "running").length;

  useEffect(() => {
    let saved: string | null = null;
    try { saved = window.localStorage.getItem("cyberdeck.theme"); } catch { /* optional */ }
    const enabled = saved !== "light";
    document.documentElement.classList.toggle("dark", enabled);
    setDark(enabled);
  }, []);

  function toggleTheme() {
    const next = !dark;
    document.documentElement.classList.toggle("dark", next);
    setDark(next);
    try { window.localStorage.setItem("cyberdeck.theme", next ? "dark" : "light"); } catch { /* optional */ }
  }

  const control = "relative flex size-10 shrink-0 items-center justify-center rounded-md text-fg-muted transition-colors hover:bg-raised hover:text-fg";

  return (
    <nav className="flex w-12 shrink-0 flex-col items-center border-r border-line bg-sidebar" aria-label="Workspace categories and controls">
      <div className="flex h-11 w-full shrink-0 items-center justify-center">
        <img src="/logo.webp" alt="CyberDeck" className="size-6 grayscale" />
      </div>
      <button type="button" onClick={wb.toggleNavigator}
        disabled={!CATEGORIES.some((item) => item.id === wb.category && item.tools.filter((tool) => !tool.disabled).length > 1)}
        title={wb.navigatorOpen ? "Collapse sidebar (Ctrl+B)" : "Expand sidebar (Ctrl+B)"}
        aria-label={wb.navigatorOpen ? "Collapse sidebar" : "Expand sidebar"}
        aria-expanded={wb.navigatorOpen} aria-controls="cyberdeck-context-navigator"
        className="flex size-10 shrink-0 items-center justify-center rounded-md text-fg-muted hover:bg-raised hover:text-fg disabled:cursor-not-allowed disabled:opacity-25">
        {wb.navigatorOpen ? <PanelLeftClose size={17} aria-hidden="true" /> : <PanelLeftOpen size={17} aria-hidden="true" />}
      </button>
      <div className="flex w-full flex-1 flex-col items-center gap-1 py-2">
        {CATEGORIES.map((category) => {
          const Icon = category.icon;
          const active = wb.category === category.id;
          const disabled = category.tools.every((tool) => tool.disabled);
          return (
            <button key={category.id} type="button"
              title={disabled ? `${category.label}: ${category.tools[0]?.disabledReason ?? "Unavailable"}` : category.label}
              aria-label={category.label} disabled={disabled}
              aria-current={active ? "page" : undefined}
              onClick={() => wb.selectCategory(category.id)}
              className={`relative flex size-10 items-center justify-center rounded-md transition-colors disabled:cursor-not-allowed disabled:opacity-35 ${active ? "bg-selected text-fg" : "text-fg-muted hover:bg-raised hover:text-fg"}`}>
              <Icon size={18} strokeWidth={active ? 2 : 1.7} aria-hidden="true" />
            </button>
          );
        })}
      </div>
      <div className="flex w-full shrink-0 flex-col items-center gap-0.5 pb-2">
        <button type="button" onClick={() => { wb.setDockTab("jobs"); wb.setDockOpen(true); }}
          aria-label={running ? `Jobs: ${running} running` : "Open jobs and console"}
          title="Jobs and console (Ctrl+J)" className={control}>
          <ListTodo size={18} aria-hidden="true" />
          {running > 0 ? <span className="absolute mb-6 ml-6 size-1.5 rounded-full bg-fg" aria-hidden="true" /> : null}
        </button>
        <button type="button" onClick={toggleTheme}
          aria-label={dark ? "Use light theme" : "Use dark theme"}
          title={dark ? "Light theme" : "Dark theme"} className={control}>
          {dark ? <Sun size={18} aria-hidden="true" /> : <Moon size={18} aria-hidden="true" />}
        </button>
        <button type="button" title="Command palette (Ctrl+K)" aria-label="Open command palette"
          onClick={() => wb.setPaletteOpen(true)} className={control}>
          <Command size={18} aria-hidden="true" />
        </button>
      </div>
    </nav>
  );
}

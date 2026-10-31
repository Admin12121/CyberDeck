"use client";
/** Status bar: transport, workspace, job state, engine status (§3.5). */
import { isDesktop } from "@lib/ipc";
import { useWorkbench } from "@state/workbench";
import { toolById } from "@features/registry";

export function StatusBar() {
  const wb = useWorkbench();
  const tool = toolById(wb.tool);
  const running = Object.values(wb.jobs).filter((j) => j.status === "running").length;

  return (
    <footer className="flex h-6 shrink-0 items-center gap-3 border-t border-line bg-sidebar px-2 font-mono text-[10px] text-fg-muted">
      <span className={isDesktop() ? "text-ok" : "text-warn"}>{isDesktop() ? "ipc: tauri" : "ipc: browser fallback"}</span>
      <span>workspace: {tool ? `${tool.category} / ${tool.label}` : wb.tool}</span>
      <span className={running > 0 ? "text-orange" : ""}>jobs: {running > 0 ? `${running} running` : "idle"}</span>
      <span className="ml-auto flex items-center gap-3">
        <button
          type="button"
          onClick={() => {
            wb.setDockTab("console");
            wb.setDockOpen(true);
          }}
          className="border border-line px-2 py-0.5 hover:border-line-strong hover:text-fg"
        >
          console (Ctrl+`)
        </button>
        <span>cyberdeck 0.1.0 · 46 native commands · darkmatter</span>
      </span>
    </footer>
  );
}

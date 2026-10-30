"use client";
/** Status bar — transport, workspace, job state, engine status (§3.5). */
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
      <span className="ml-auto">hacktool 0.1.0 · arc 1 · darkmatter</span>
    </footer>
  );
}

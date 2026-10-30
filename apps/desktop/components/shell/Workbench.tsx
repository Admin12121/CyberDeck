"use client";
/**
 * Workbench shell — the common desktop layout every studio plugs into
 * (Master Plan §3.4): title bar, category rail, navigator, active workspace,
 * inspector, bottom dock, status bar, command palette.
 */
import { WorkbenchProvider, useWorkbench } from "@state/workbench";
import { toolById } from "@features/registry";
import { CryptoWorkspace } from "@features/crypto";
import { NetworkWorkspace } from "@features/network";
import { WebWorkspace } from "@features/web";
import { ReverseWorkspace } from "@features/reverse";
import { ForensicsWorkspace } from "@features/forensics";
import { Rail } from "./Rail";
import { Navigator } from "./Navigator";
import { Inspector } from "./Inspector";
import { JobsDock } from "./JobsDock";
import { StatusBar } from "./StatusBar";
import { CommandPalette } from "./CommandPalette";

function TitleBar() {
  const wb = useWorkbench();
  const tool = toolById(wb.tool);
  return (
    <header
      data-tauri-drag-region
      className="flex h-9 shrink-0 items-center gap-3 border-b border-line bg-sidebar px-3"
    >
      <div className="flex h-4 w-4 items-center justify-center bg-blue font-mono text-[9px] font-bold text-app">H</div>
      <span className="text-xs font-medium text-fg">HackTool</span>
      <span className="font-mono text-[10px] text-fg-muted">Case: Scratchpad</span>
      <span className="mx-1 h-4 w-px bg-line" />
      <span className="text-xs text-fg-dim">{tool ? `${tool.label}` : ""}</span>
      <span className="ml-auto font-mono text-[10px] text-fg-muted">
        <button type="button" onClick={() => wb.setPaletteOpen(true)} className="border border-line px-2 py-0.5 hover:border-line-strong hover:text-fg">
          Ctrl K — commands
        </button>
      </span>
    </header>
  );
}

function ActiveWorkspace() {
  const wb = useWorkbench();
  switch (wb.category) {
    case "crypto":
      return <CryptoWorkspace tool={wb.tool} />;
    case "network":
      return <NetworkWorkspace tool={wb.tool} />;
    case "web":
      return <WebWorkspace tool={wb.tool} />;
    case "reverse":
      return <ReverseWorkspace />;
    case "forensics":
      return <ForensicsWorkspace tool={wb.tool} />;
  }
}

function Shell() {
  const wb = useWorkbench();
  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden">
      <TitleBar />
      <div className="flex min-h-0 flex-1">
        <Rail />
        <Navigator />
        <main className="min-w-0 flex-1 overflow-hidden bg-app" aria-label="Active workspace">
          <ActiveWorkspace />
        </main>
        {wb.inspectorOpen ? <Inspector /> : null}
      </div>
      <JobsDock />
      <StatusBar />
      <CommandPalette />
    </div>
  );
}

export function Workbench() {
  return (
    <WorkbenchProvider>
      <Shell />
    </WorkbenchProvider>
  );
}

"use client";
/**
 * Workbench shell: the common desktop layout every studio plugs into
 * (Master Plan §3.4). Navigator, inspector and dock are resizable with
 * clamped min/max via drag handles.
 */
import { WorkbenchProvider, useWorkbench } from "@state/workbench";
import { PANEL_LIMITS } from "@state/workbench";
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
import { Resizer } from "@ds/Resizer";

function TitleBar() {
  const wb = useWorkbench();
  const tool = toolById(wb.tool);
  return (
    <header
      data-tauri-drag-region
      className="flex h-9 shrink-0 items-center gap-3 border-b border-line bg-sidebar px-3"
    >
      <img src="/logo.webp" alt="" aria-hidden className="h-5 w-5" />
      <span className="text-xs font-medium text-fg">HackTool</span>
      <span className="font-mono text-[10px] text-fg-muted">Case: Scratchpad</span>
      <span className="mx-1 h-4 w-px bg-line" />
      <span className="text-xs text-fg-dim">{tool ? `${tool.label}` : ""}</span>
      <span className="ml-auto font-mono text-[10px] text-fg-muted">
        <button type="button" onClick={() => wb.setPaletteOpen(true)} className="border border-line px-2 py-0.5 hover:border-line-strong hover:text-fg">
          Ctrl K · commands
        </button>
      </span>
    </header>
  );
}

/**
 * Every category stays mounted; hidden ones keep their state so users can
 * hop between tools without losing work (Master Plan §3.5: no data loss on
 * workspace switching).
 */
function ActiveWorkspace() {
  const wb = useWorkbench();
  const show = (id: string) => (wb.category === id ? "h-full" : "hidden h-full");
  return (
    <>
      <div className={show("crypto")}><CryptoWorkspace tool={wb.tool} /></div>
      <div className={show("network")}><NetworkWorkspace tool={wb.tool} /></div>
      <div className={show("web")}><WebWorkspace tool={wb.tool} /></div>
      <div className={show("reverse")}><ReverseWorkspace /></div>
      <div className={show("forensics")}><ForensicsWorkspace tool={wb.tool} /></div>
    </>
  );
}

function Shell() {
  const wb = useWorkbench();
  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden">
      <TitleBar />
      <div className="flex min-h-0 flex-1">
        <Rail />
        <Navigator />
        <Resizer
          direction="horizontal"
          ariaLabel="Resize navigator"
          value={wb.navigatorWidth}
          onChange={wb.setNavigatorWidth}
          min={PANEL_LIMITS.navigator.min}
          max={PANEL_LIMITS.navigator.max}
        />
        <main className="min-w-0 flex-1 overflow-hidden bg-app" aria-label="Active workspace">
          <ActiveWorkspace />
        </main>
        {wb.inspectorOpen ? (
          <>
            <Resizer
              direction="horizontal"
              flip
              ariaLabel="Resize inspector"
              value={wb.inspectorWidth}
              onChange={wb.setInspectorWidth}
              min={PANEL_LIMITS.inspector.min}
              max={PANEL_LIMITS.inspector.max}
            />
            <Inspector />
          </>
        ) : null}
      </div>
      {wb.dockOpen ? (
        <>
          <Resizer
            direction="vertical"
            flip
            ariaLabel="Resize jobs dock"
            value={wb.dockHeight}
            onChange={wb.setDockHeight}
            min={PANEL_LIMITS.dock.min}
            max={PANEL_LIMITS.dock.max}
          />
          <JobsDock />
        </>
      ) : null}
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

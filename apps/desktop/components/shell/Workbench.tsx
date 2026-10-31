"use client";
/**
 * Workbench shell: logo rail + workspace column. Every category stays
 * mounted; hidden ones keep their state across switches (Master Plan §3.5).
 */
import { WorkbenchProvider, useWorkbench } from "@state/workbench";
import { PANEL_LIMITS } from "@state/workbench";
import { CryptoWorkspace } from "@features/crypto";
import { NetworkWorkspace } from "@features/network";
import { WebWorkspace } from "@features/web";
import { ReverseWorkspace } from "@features/reverse";
import { ForensicsWorkspace } from "@features/forensics";
import { Rail } from "./Rail";
import { BottomDock } from "./BottomDock";
import { StatusBar } from "./StatusBar";
import { CommandPalette } from "./CommandPalette";
import { Resizer } from "@ds/Resizer";

/**
 * Every category stays mounted; hidden ones keep their state so users can
 * hop between tools without losing work (Master Plan §3.5).
 */
function ActiveWorkspace() {
  const wb = useWorkbench();
  const show = (id: string) => (wb.category === id ? "h-full" : "hidden h-full");
  return (
    <>
      <div className={show("crypto")}><CryptoWorkspace tool={wb.tool} /></div>
      <div className={show("network")}><NetworkWorkspace tool={wb.tool} /></div>
      <div className={show("web")}><WebWorkspace /></div>
      <div className={show("reverse")}><ReverseWorkspace /></div>
      <div className={show("forensics")}><ForensicsWorkspace tool={wb.tool} /></div>
    </>
  );
}

function Shell() {
  const wb = useWorkbench();
  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden">
      <div className="flex min-h-0 flex-1">
        <Rail />
        <div className="flex min-w-0 flex-1 flex-col">
          <main className="min-h-0 flex-1 overflow-hidden bg-app" aria-label="Active workspace">
            <ActiveWorkspace />
          </main>
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
              <BottomDock />
            </>
          ) : null}
        </div>
      </div>
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

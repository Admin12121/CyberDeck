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
import { ContextNavigator } from "./ContextNavigator";
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
    <div className="flex h-screen w-screen overflow-hidden">
      <Rail />
      <div className="flex min-h-0 min-w-0 flex-1 flex-col">
        <div className="flex min-h-0 min-w-0 flex-1">
          {wb.navigatorOpen ? (
            <>
              <button type="button" aria-label="Close tool sidebar" onClick={wb.toggleNavigator}
                className="fixed inset-y-0 left-12 right-0 z-20 bg-black/45 min-[1080px]:hidden" />
              <div className="fixed inset-y-0 left-12 z-30 flex max-w-[calc(100vw-3rem)] min-[1080px]:contents">
                <ContextNavigator />
                <div className="hidden min-[1080px]:contents">
                  <Resizer direction="horizontal" ariaLabel="Resize contextual navigator" value={wb.navigatorWidth}
                    onChange={wb.setNavigatorWidth} resetValue={PANEL_LIMITS.navigator.fallback}
                    min={PANEL_LIMITS.navigator.min} max={PANEL_LIMITS.navigator.max} />
                </div>
              </div>
            </>
          ) : null}
          <div className="flex min-h-0 min-w-0 flex-1 flex-col">
            <main className="min-h-0 flex-1 overflow-hidden bg-app" aria-label="Active workspace">
              <ActiveWorkspace />
            </main>
            <div className={wb.dockOpen ? "contents" : "hidden"}>
              <Resizer direction="vertical" flip ariaLabel="Resize dock"
                value={wb.dockHeight} resetValue={PANEL_LIMITS.dock.fallback}
                onChange={wb.setDockHeight} min={PANEL_LIMITS.dock.min} max={PANEL_LIMITS.dock.max} />
              <BottomDock />
            </div>
          </div>
        </div>
        <StatusBar />
      </div>
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

"use client";

import type { ReactNode } from "react";
import { usePathname } from "next/navigation";
import { WorkbenchProvider, useWorkbenchLayout } from "@state/workbench";
import { WorkspaceSessionProvider } from "@state/workspace-sessions";
import { JobNotificationProvider } from "@state/job-notifications";
import { PANEL_LIMITS } from "@state/panel-preferences";
import { Rail } from "./Rail";
import { ContextNavigator } from "./ContextNavigator";
import { BottomDock } from "./BottomDock";
import { StatusBar } from "./StatusBar";
import { CommandPalette } from "./CommandPalette";
import { Resizer } from "@ds/Resizer";

function DesktopFrame({ children }: { children: ReactNode }) {
  const path = usePathname();
  const ui = useWorkbenchLayout();
  const home = path === "/";
  return (
    <div className="flex h-dvh w-full min-w-0 overflow-hidden bg-app">
      <Rail />
      <div className="flex min-h-0 min-w-0 flex-1 flex-col">
        <div className="flex min-h-0 min-w-0 flex-1">
          {!home && ui.navigatorOpen ? (
            <>
              <button type="button" aria-label="Close tool sidebar" onClick={ui.toggleNavigator}
                className="fixed inset-y-0 left-12 right-0 z-20 bg-black/45 min-[1080px]:hidden" />
              <div className="fixed inset-y-0 left-12 z-30 flex max-w-[calc(100vw-3rem)] min-[1080px]:contents">
                <ContextNavigator />
                <div className="hidden min-[1080px]:contents">
                  <Resizer direction="horizontal" ariaLabel="Resize contextual navigator"
                    value={ui.navigatorWidth} onChange={ui.setNavigatorWidth}
                    resetValue={PANEL_LIMITS.navigator.fallback}
                    min={PANEL_LIMITS.navigator.min} max={PANEL_LIMITS.navigator.max} />
                </div>
              </div>
            </>
          ) : null}
          <div className="flex min-h-0 min-w-0 flex-1 flex-col">
            <main className="min-h-0 flex-1 overflow-hidden bg-app" aria-label={home ? "CyberDeck Home" : "Active workspace"}>
              {children}
            </main>
            <div className={!home && ui.dockOpen ? "contents" : "hidden"}>
              <Resizer direction="vertical" flip ariaLabel="Resize dock"
                value={ui.dockHeight} resetValue={PANEL_LIMITS.dock.fallback}
                onChange={ui.setDockHeight} min={PANEL_LIMITS.dock.min} max={PANEL_LIMITS.dock.max} />
              <BottomDock />
            </div>
          </div>
        </div>
        {!home && <StatusBar />}
      </div>
      <CommandPalette />
    </div>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <WorkbenchProvider>
      <WorkspaceSessionProvider>
        <JobNotificationProvider>
          <DesktopFrame>{children}</DesktopFrame>
        </JobNotificationProvider>
      </WorkspaceSessionProvider>
    </WorkbenchProvider>
  );
}

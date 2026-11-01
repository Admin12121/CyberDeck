"use client";
/** Web studio: ZAP-model workspace with top-bar tabs (Master Plan 5.2). */
import { WorkspaceTabs } from "@ds/panes";
import { WebWorkflowProvider, useWebWorkflow, type WebTab } from "./WebWorkflow";
import { HistoryView } from "./HistoryView";
import { ProxyView } from "./ProxyView";
import { ProxyCertificateAction } from "./ProxyCertificateAction";
import { RepeaterView } from "./RepeaterView";
import { ScannerView } from "./ScannerView";
import { SpiderView } from "./SpiderView";

function WebWorkspaceContent() {
  const { tab, setTab } = useWebWorkflow();
  const show = (id: string) => (tab === id ? "h-full" : "hidden h-full");
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="relative shrink-0">
        <WorkspaceTabs items={["proxy", "history", "repeater", "scanner", "spider"] as WebTab[]}
          active={tab} onChange={setTab} ariaLabel="Web Studio tools" />
        {tab === "proxy" && (
          <div className="absolute inset-y-0 right-2 z-10 flex items-center">
            <ProxyCertificateAction />
          </div>
        )}
      </div>
      <div className="min-h-0 flex-1">
        <div className={show("proxy")}><ProxyView /></div>
        <div className={show("history")}><HistoryView /></div>
        <div className={show("repeater")}><RepeaterView /></div>
        <div className={show("scanner")}><ScannerView /></div>
        <div className={show("spider")}><SpiderView /></div>
      </div>
    </div>
  );
}

export function WebWorkspace() {
  return <WebWorkflowProvider><WebWorkspaceContent /></WebWorkflowProvider>;
}

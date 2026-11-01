"use client";
/** Web studio: ZAP-model workspace with top-bar tabs (Master Plan 5.2). */
import { WorkspaceTabs } from "@ds/panes";
import { WebWorkflowProvider, useWebWorkflow, type WebTab } from "./WebWorkflow";
import { HistoryView } from "./HistoryView";
import { ProxyView } from "./ProxyView";
import { RepeaterView } from "./RepeaterView";
import { ScannerView } from "./ScannerView";
import { SpiderView } from "./SpiderView";

function WebWorkspaceContent() {
  const { tab, setTab } = useWebWorkflow();
  const show = (id: string) => (tab === id ? "h-full" : "hidden h-full");
  return (
    <div className="flex h-full min-h-0 flex-col">
      <WorkspaceTabs items={["proxy", "history", "repeater", "scanner", "spider"] as WebTab[]}
        active={tab} onChange={setTab} ariaLabel="Web Studio tools" />
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

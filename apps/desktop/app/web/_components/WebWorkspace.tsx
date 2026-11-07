"use client";
/** Web studio: ZAP-model workspace with top-bar tabs (Master Plan 5.2). */
import { CategoryWorkspace } from "@ds/compact";
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
      <CategoryWorkspace
        activeId={tab}
        views={[
          { id: "proxy", render: () => <ProxyView /> },
          { id: "history", render: () => <HistoryView /> },
          { id: "repeater", render: () => <RepeaterView /> },
          { id: "scanner", render: () => <ScannerView /> },
          { id: "spider", render: () => <SpiderView /> },
        ]}
      />
    </div>
  );
}

export function WebWorkspace() {
  return <WebWorkflowProvider><WebWorkspaceContent /></WebWorkflowProvider>;
}

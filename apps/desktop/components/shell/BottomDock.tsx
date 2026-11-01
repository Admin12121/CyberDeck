"use client";

import { useEffect, useRef, useState, type DragEvent } from "react";
import { Columns2, Rows2, Plus, X } from "lucide-react";
import { useWorkbench } from "@state/workbench";
import { Resizer } from "@ds/Resizer";
import { ConsoleDock } from "./ConsoleDock";
import { JobsDock, JobDetail } from "./JobsDock";
import {
  closeDockTab, dockPanes, dockTabs, initialDock, insertDockTab,
  moveDockTab, resizeDockSplit, selectDockTab,
  type DockEdge, type DockNode, type DockTabId,
} from "./dock-layout";

const MAX_PANES = 4;
const MAX_CONSOLES = 5;

function tabLabel(tab: DockTabId): string {
  if (tab === "jobs") return "Jobs";
  if (tab.startsWith("job-")) return `Job ${tab.slice(4)}`;
  return `Console ${tab.slice(9)}`;
}

function dropEdge(event: DragEvent<HTMLElement>): DockEdge {
  const rect = event.currentTarget.getBoundingClientRect();
  const x = (event.clientX - rect.left) / rect.width;
  const y = (event.clientY - rect.top) / rect.height;
  if (x < 0.24) return "left";
  if (x > 0.76) return "right";
  if (y < 0.25) return "top";
  if (y > 0.75) return "bottom";
  return "center";
}

function SplitView({
  node, onRatio, children,
}: {
  node: Extract<DockNode, { kind: "split" }>;
  onRatio: (id: string, ratio: number) => void;
  children: (node: DockNode) => React.ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState(800);
  const horizontal = node.axis === "horizontal";
  useEffect(() => {
    if (!ref.current) return;
    const observer = new ResizeObserver(([entry]) =>
      setSize(horizontal ? entry.contentRect.width : entry.contentRect.height));
    observer.observe(ref.current);
    return () => observer.disconnect();
  }, [horizontal]);
  const length = Math.max(1, size);
  const handle = node.ratio * length;
  return (
    <div ref={ref} className={`flex h-full min-h-0 min-w-0 flex-1 ${horizontal ? "flex-row" : "flex-col"}`}>
      <div className="min-h-0 min-w-0 overflow-hidden" style={{
        [horizontal ? "width" : "height"]: `calc(${node.ratio * 100}% - 0.5px)`,
      }}>{children(node.first)}</div>
      <Resizer direction={horizontal ? "horizontal" : "vertical"}
        ariaLabel={horizontal ? "Resize dock columns" : "Resize dock rows"}
        value={handle} min={length * 0.2} max={length * 0.8}
        onChange={(next) => onRatio(node.id, next / length)}
        resetValue={length / 2} />
      <div className="min-h-0 min-w-0 flex-1 overflow-hidden">{children(node.second)}</div>
    </div>
  );
}

export function BottomDock() {
  const wb = useWorkbench();
  const [tree, setTree] = useState<DockNode>(initialDock);
  const [dropTarget, setDropTarget] = useState<{ paneId: string; edge: DockEdge } | null>(null);
  const idCounter = useRef(0);
  const seenJobs = useRef(new Set<number>());
  const panes = dockPanes(tree);
  const tabs = dockTabs(tree);
  const nextId = () => `dock-node-${++idCounter.current}`;

  useEffect(() => {
    seenJobs.current.clear();
    setTree((previous) => dockTabs(previous).filter((tab) => tab.startsWith("job-"))
      .reduce((current, tab) => closeDockTab(current, tab), previous));
  }, [wb.caseId]);

  useEffect(() => {
    for (const id of Object.keys(wb.jobs).map(Number)) {
      if (seenJobs.current.has(id)) continue;
      seenJobs.current.add(id);
      setTree((previous) => {
        if (dockTabs(previous).filter((tab) => tab.startsWith("job-")).length >= 12) return previous;
        const pane = dockPanes(previous).find((item) => item.tabs.includes("jobs")) ?? dockPanes(previous)[0];
        return insertDockTab(previous, pane.id, `job-${id}`, false);
      });
    }
  }, [wb.jobs]);

  useEffect(() => {
    const tab: DockTabId = wb.dockTab === "jobs" ? "jobs" : "terminal-1";
    setTree((previous) => {
      if (wb.dockTab === "console" && dockPanes(previous).some((pane) => pane.active.startsWith("terminal-"))) return previous;
      const target = dockPanes(previous).find((pane) => pane.tabs.includes(tab));
      if (target) return selectDockTab(previous, target.id, tab);
      return insertDockTab(previous, dockPanes(previous)[0].id, tab);
    });
  }, [wb.dockTab]);

  function newConsole(paneId: string): DockTabId | null {
    const available = Array.from({ length: MAX_CONSOLES }, (_, index) => `terminal-${index + 1}` as DockTabId)
      .find((tab) => !tabs.includes(tab));
    if (!available) return null;
    setTree((previous) => insertDockTab(previous, paneId, available));
    return available;
  }

  function splitPane(paneId: string, edge: "right" | "bottom") {
    if (panes.length >= MAX_PANES) return;
    const pane = panes.find((item) => item.id === paneId);
    if (!pane) return;
    if (pane.tabs.length > 1) {
      setTree((previous) => moveDockTab(previous, pane.active, paneId, edge, nextId(), nextId()));
    } else {
      const next = Array.from({ length: MAX_CONSOLES }, (_, index) => `terminal-${index + 1}` as DockTabId)
        .find((tab) => !tabs.includes(tab));
      if (!next) return;
      setTree((previous) => {
        const inserted = insertDockTab(previous, paneId, next);
        return moveDockTab(inserted, next, paneId, edge, nextId(), nextId());
      });
    }
  }

  function move(tab: DockTabId, paneId: string, edge: DockEdge) {
    if (edge !== "center" && panes.length >= MAX_PANES) return;
    setTree((previous) => moveDockTab(previous, tab, paneId, edge, nextId(), nextId()));
  }

  function renderNode(node: DockNode): React.ReactNode {
    if (node.kind === "split") return (
      <SplitView key={node.id} node={node}
        onRatio={(id, ratio) => setTree((previous) => resizeDockSplit(previous, id, ratio))}>
        {renderNode}
      </SplitView>
    );
    const hasConsoleSlot = tabs.filter((tab) => tab.startsWith("terminal-")).length < MAX_CONSOLES;
    const canSplit = panes.length < MAX_PANES && (node.tabs.length > 1 || hasConsoleSlot);
    const highlight = dropTarget?.paneId === node.id ? dropTarget.edge : null;
    return (
      <section key={node.id} aria-label="Dock panel" className="relative flex h-full min-h-0 min-w-0 flex-1 flex-col bg-panel"
        onDragOver={(event) => {
          if (!event.dataTransfer.types.includes("text/plain")) return;
          event.preventDefault();
          event.dataTransfer.dropEffect = "move";
          setDropTarget({ paneId: node.id, edge: dropEdge(event) });
        }}
        onDragLeave={(event) => {
          if (!event.currentTarget.contains(event.relatedTarget as Node)) setDropTarget(null);
        }}
        onDrop={(event) => {
          event.preventDefault();
          const source = event.dataTransfer.getData("text/plain") as DockTabId;
          if (tabs.includes(source)) move(source, node.id, dropEdge(event));
          setDropTarget(null);
        }}>
        <div role="tablist" aria-label="Dock tabs"
          className="flex h-9 shrink-0 items-center gap-0.5 overflow-x-auto border-b border-line bg-sidebar px-1">
          {node.tabs.map((tab) => (
            <div key={tab} className={`flex h-7 shrink-0 items-center rounded-md ${node.active === tab ? "bg-selected text-fg" : "text-fg-muted hover:bg-raised"}`}>
              <button type="button" role="tab" aria-selected={node.active === tab}
                aria-controls={`dock-content-${tab}`}
                draggable
                onDragStart={(event) => {
                  event.dataTransfer.setData("text/plain", tab);
                  event.dataTransfer.effectAllowed = "move";
                }}
                onDragEnd={() => setDropTarget(null)}
                onClick={() => {
                  setTree((prev) => selectDockTab(prev, node.id, tab));
                  wb.setDockTab(tab.startsWith("terminal-") ? "console" : "jobs");
                }}
                onKeyDown={(event) => {
                  if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
                  event.preventDefault();
                  const index = node.tabs.indexOf(tab);
                  const next = node.tabs[(index + (event.key === "ArrowRight" ? 1 : -1) + node.tabs.length) % node.tabs.length];
                  setTree((prev) => selectDockTab(prev, node.id, next));
                  document.getElementById(`dock-tab-${next}`)?.focus();
                }}
                id={`dock-tab-${tab}`}
                title="Drag to move; drop on a pane edge to split"
                className="h-7 px-2 text-xs">{tabLabel(tab)}</button>
              {tab !== "jobs" && (
                <button type="button" title={`Close ${tabLabel(tab)}`} aria-label={`Close ${tabLabel(tab)}`}
                  onClick={() => setTree((prev) => closeDockTab(prev, tab))}
                  className="mr-1 rounded p-0.5 hover:bg-raised"><X size={12} aria-hidden="true" /></button>
              )}
            </div>
          ))}
          <button type="button" aria-label="New console" title="New CyberDeck command console (maximum five)"
            disabled={!hasConsoleSlot} onClick={() => newConsole(node.id)}
            className="flex size-7 shrink-0 items-center justify-center rounded-md text-fg-muted hover:bg-raised disabled:opacity-30">
            <Plus size={15} />
          </button>
          <div className="ml-auto flex shrink-0 items-center gap-0.5">
            <button type="button" onClick={() => splitPane(node.id, "right")} disabled={!canSplit}
              title="Split pane right" aria-label="Split pane right"
              className="flex size-7 items-center justify-center rounded-md text-fg-muted hover:bg-raised disabled:opacity-30">
              <Columns2 size={14} />
            </button>
            <button type="button" onClick={() => splitPane(node.id, "bottom")} disabled={!canSplit}
              title="Split pane below" aria-label="Split pane below"
              className="flex size-7 items-center justify-center rounded-md text-fg-muted hover:bg-raised disabled:opacity-30">
              <Rows2 size={14} />
            </button>
            <button type="button" title="Close dock" aria-label="Close dock" onClick={() => wb.setDockOpen(false)}
              className="flex size-7 items-center justify-center rounded-md text-fg-muted hover:bg-raised">
              <X size={15} />
            </button>
          </div>
        </div>
        <div className="min-h-0 flex-1">
          {node.tabs.map((tab) => (
            <div key={tab} id={`dock-content-${tab}`} role="tabpanel" aria-labelledby={`dock-tab-${tab}`}
              className={node.active === tab ? "h-full min-h-0" : "hidden"}>
              {tab === "jobs" ? <JobsDock /> : tab.startsWith("job-") ?
                <JobDetail jobId={Number(tab.slice(4))} /> :
                <ConsoleDock terminalId={tab} />}
            </div>
          ))}
        </div>
        {highlight && (
          <div aria-hidden="true" className={`pointer-events-none absolute z-20 border border-ring bg-selected/25 ${
            highlight === "center" ? "inset-1" :
            highlight === "left" ? "inset-y-1 left-1 w-1/3" :
            highlight === "right" ? "inset-y-1 right-1 w-1/3" :
            highlight === "top" ? "inset-x-1 top-1 h-1/3" : "inset-x-1 bottom-1 h-1/3"
          }`} />
        )}
      </section>
    );
  }

  return (
    <div className="flex min-h-0 shrink-0 flex-col bg-panel" style={{ height: wb.dockHeight }}
      onDragEnd={() => setDropTarget(null)}>
      {renderNode(tree)}
    </div>
  );
}

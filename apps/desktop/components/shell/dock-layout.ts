export type DockTabId = "jobs" | `terminal-${number}` | `job-${number}`;
export type DockEdge = "center" | "left" | "right" | "top" | "bottom";

export type DockNode =
  | { kind: "pane"; id: string; tabs: DockTabId[]; active: DockTabId }
  | { kind: "split"; id: string; axis: "horizontal" | "vertical"; ratio: number; first: DockNode; second: DockNode };

export const initialDock: DockNode = {
  kind: "pane", id: "dock-main", tabs: ["jobs", "terminal-1"], active: "jobs",
};

export function dockPanes(root: DockNode): Extract<DockNode, { kind: "pane" }>[] {
  return root.kind === "pane" ? [root] : [...dockPanes(root.first), ...dockPanes(root.second)];
}

export function dockTabs(root: DockNode): DockTabId[] {
  return dockPanes(root).flatMap((pane) => pane.tabs);
}

export function selectDockTab(node: DockNode, paneId: string, tab: DockTabId): DockNode {
  if (node.kind === "pane") {
    return node.id === paneId && node.tabs.includes(tab) ? { ...node, active: tab } : node;
  }
  return { ...node, first: selectDockTab(node.first, paneId, tab), second: selectDockTab(node.second, paneId, tab) };
}

export function insertDockTab(node: DockNode, paneId: string, tab: DockTabId, activate = true): DockNode {
  if (dockTabs(node).includes(tab)) return node;
  if (node.kind === "pane") {
    return node.id === paneId ? { ...node, tabs: [...node.tabs, tab], active: activate ? tab : node.active } : node;
  }
  return { ...node, first: insertDockTab(node.first, paneId, tab, activate), second: insertDockTab(node.second, paneId, tab, activate) };
}

function removeTab(node: DockNode, tab: DockTabId): DockNode | null {
  if (node.kind === "pane") {
    if (!node.tabs.includes(tab)) return node;
    const tabs = node.tabs.filter((item) => item !== tab);
    return tabs.length ? { ...node, tabs, active: node.active === tab ? tabs[0] : node.active } : null;
  }
  const first = removeTab(node.first, tab);
  const second = removeTab(node.second, tab);
  if (!first) return second;
  if (!second) return first;
  return { ...node, first, second };
}

export function closeDockTab(node: DockNode, tab: DockTabId): DockNode {
  return removeTab(node, tab) ?? { kind: "pane", id: "dock-main", tabs: ["jobs"], active: "jobs" };
}

export function moveDockTab(
  node: DockNode, tab: DockTabId, targetId: string, edge: DockEdge, newPaneId: string, newSplitId: string,
): DockNode {
  const source = dockPanes(node).find((pane) => pane.tabs.includes(tab));
  const target = dockPanes(node).find((pane) => pane.id === targetId);
  if (!source || !target) return node;
  if (source.id === targetId && (edge === "center" || source.tabs.length === 1)) return node;
  const without = removeTab(node, tab);
  if (!without || !dockPanes(without).some((pane) => pane.id === targetId)) return node;
  const place = (current: DockNode): DockNode => {
    if (current.kind === "split") return { ...current, first: place(current.first), second: place(current.second) };
    if (current.id !== targetId) return current;
    if (edge === "center") return { ...current, tabs: [...current.tabs, tab], active: tab };
    const added: DockNode = { kind: "pane", id: newPaneId, tabs: [tab], active: tab };
    const before = edge === "top" || edge === "left";
    return {
      kind: "split", id: newSplitId,
      axis: edge === "top" || edge === "bottom" ? "vertical" : "horizontal",
      ratio: 0.5, first: before ? added : current, second: before ? current : added,
    };
  };
  return place(without);
}

export function resizeDockSplit(node: DockNode, splitId: string, ratio: number): DockNode {
  if (node.kind === "pane") return node;
  if (node.id === splitId) return { ...node, ratio: Math.max(0.2, Math.min(0.8, ratio)) };
  return { ...node, first: resizeDockSplit(node.first, splitId, ratio), second: resizeDockSplit(node.second, splitId, ratio) };
}

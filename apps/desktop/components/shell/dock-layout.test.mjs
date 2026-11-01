import assert from "node:assert/strict";
import { test } from "node:test";
import {
  initialDock, dockPanes, dockTabs, insertDockTab, moveDockTab,
  closeDockTab, selectDockTab, resizeDockSplit,
} from "./dock-layout.ts";

test("tabs are unique and can be selected without changing the layout", () => {
  assert.deepEqual(dockTabs(initialDock), ["jobs", "terminal-1"]);
  const selected = selectDockTab(initialDock, "dock-main", "terminal-1");
  assert.equal(dockPanes(selected)[0].active, "terminal-1");
  assert.deepEqual(dockTabs(insertDockTab(selected, "dock-main", "terminal-1")), ["jobs", "terminal-1"]);
});

test("drag a tab right or below creates real nested 2x2 dock regions", () => {
  let tree = moveDockTab(initialDock, "terminal-1", "dock-main", "right", "pane2", "split1");
  assert.equal(tree.kind, "split");
  assert.equal(tree.axis, "horizontal");
  assert.equal(dockPanes(tree).length, 2);
  tree = insertDockTab(tree, "dock-main", "terminal-2");
  tree = moveDockTab(tree, "terminal-2", "dock-main", "bottom", "pane3", "split2");
  assert.equal(dockPanes(tree).length, 3);
  tree = insertDockTab(tree, "pane2", "terminal-3");
  tree = moveDockTab(tree, "terminal-3", "pane2", "bottom", "pane4", "split3");
  assert.equal(dockPanes(tree).length, 4);
  assert.equal(new Set(dockTabs(tree)).size, dockTabs(tree).length);
  assert.equal(dockTabs(tree).length, 4);
});

test("moving tabs back to center removes empty panes and preserves the jobs tab", () => {
  let tree = moveDockTab(initialDock, "terminal-1", "dock-main", "right", "other", "split");
  tree = moveDockTab(tree, "terminal-1", "dock-main", "center", "unused", "unused2");
  assert.equal(dockPanes(tree).length, 1);
  assert.deepEqual(dockTabs(tree), ["jobs", "terminal-1"]);
  tree = closeDockTab(tree, "terminal-1");
  assert.deepEqual(dockTabs(tree), ["jobs"]);
  assert.deepEqual(dockPanes(moveDockTab(tree, "jobs", "dock-main", "left", "pane", "split")).length, 1);
});

test("move and close an active job tab without losing the remaining tabs", () => {
  let tree = insertDockTab(initialDock, "dock-main", "job--2");
  assert.equal(dockPanes(tree)[0].active, "job--2");
  tree = closeDockTab(tree, "job--2");
  assert.deepEqual(dockTabs(tree), ["jobs", "terminal-1"]);
  assert.equal(dockPanes(tree)[0].active, "jobs");
});

test("resize ratio is bounded and keeps other split branches unchanged", () => {
  const tree = moveDockTab(initialDock, "terminal-1", "dock-main", "top", "other", "split");
  assert.equal(tree.axis, "vertical");
  assert.equal(resizeDockSplit(tree, "split", -1).ratio, 0.2);
  assert.equal(resizeDockSplit(tree, "split", 10).ratio, 0.8);
  assert.equal(resizeDockSplit(tree, "unknown", 0.3).ratio, 0.5);
});

test("background job tabs do not steal the currently selected console", () => {
  const selected = selectDockTab(initialDock, "dock-main", "terminal-1");
  const updated = insertDockTab(selected, "dock-main", "job-4", false);
  assert.equal(dockPanes(updated)[0].active, "terminal-1");
  assert.deepEqual(dockTabs(updated), ["jobs", "terminal-1", "job-4"]);
});

test("moving a tab into an adjacent pane preserves its identity and collapses a source leaf", () => {
  let tree = moveDockTab(initialDock, "terminal-1", "dock-main", "right", "right", "split");
  tree = insertDockTab(tree, "right", "terminal-2");
  tree = moveDockTab(tree, "terminal-1", "dock-main", "center", "unused", "unused2");
  assert.equal(dockPanes(tree).length, 2);
  assert.equal(new Set(dockTabs(tree)).size, 3);
  tree = moveDockTab(tree, "terminal-2", "dock-main", "center", "unused3", "unused4");
  assert.equal(dockPanes(tree).length, 1);
  assert.deepEqual(dockTabs(tree), ["jobs", "terminal-1", "terminal-2"]);
});

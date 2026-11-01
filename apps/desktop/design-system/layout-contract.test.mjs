import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import path from "node:path";

const desktop = path.resolve(import.meta.dirname, "..");
const source = (relative) => fs.readFileSync(path.join(desktop, relative), "utf8");
const features = ["crypto", "network", "forensics", "web"];
const views = [];
for (const feature of features) {
  const directory = path.join(desktop, "app", feature, "_components");
  for (const file of fs.readdirSync(directory)) {
    if (file.endsWith(".tsx")) views.push(path.join(directory, file));
  }
}

test("all feature toolbar geometry is sourced from the common design contract", () => {
  assert.match(source("app/globals.css"), /--cd-toolbar-height:\s*36px/);
  assert.match(source("app/globals.css"), /\.cd-workspace-toolbar\s*\{/);
  assert.match(source("design-system/panes.tsx"), /className="cd-workspace-toolbar/);
  for (const file of views) {
    const text = fs.readFileSync(file, "utf8");
    assert.doesNotMatch(text, /className="flex h-(?:8|9) [^"]*border-b border-line bg-sidebar/, file);
  }
});

test("workspace navigation lives in the sidebar, not duplicated tool tabs", () => {
  for (const category of ["crypto", "network", "forensics"]) {
    const directory = path.join(desktop, "app", category, "_components");
    for (const file of fs.readdirSync(directory).filter((name) => name.endsWith(".tsx"))) {
      assert.doesNotMatch(fs.readFileSync(path.join(directory, file), "utf8"), /<ToolTabs\b|@shell\/ToolTabs/, file);
    }
  }
  assert.match(source("components/shell/ContextNavigator.tsx"), /cd-workspace-toolbar/);
});

test("Web and Packet views use the same local tab primitive", () => {
  assert.match(source("design-system/panes.tsx"), /export function WorkspaceTabs/);
  assert.match(source("app/web/_components/WebWorkspace.tsx"), /<WorkspaceTabs\b/);
  assert.match(source("app/network/_components/PacketStudioView.tsx"), /<WorkspaceTabs\b/);
});

test("all browser exports use one checked helper rather than local anchor implementations", () => {
  for (const view of [
    "app/crypto/_components/RecipesView.tsx",
    "app/forensics/_components/CaseFindingsView.tsx",
    "app/web/_components/ProxyCertificateAction.tsx",
  ]) {
    assert.match(source(view), /downloadContent\(/);
    assert.doesNotMatch(source(view), /URL\.createObjectURL\(/);
  }
  assert.match(source("lib/download.ts"), /Cannot download empty content/);
});

test("shell and status bar consume focused state contexts rather than terminal/job state", () => {
  const shell = source("components/shell/AppShell.tsx");
  const status = source("components/shell/StatusBar.tsx");
  const navigator = source("components/shell/ContextNavigator.tsx");
  assert.match(shell, /useWorkbenchLayout/);
  assert.match(source("app/crypto/page.tsx"), /useWorkbenchLocation/);
  assert.doesNotMatch(shell, /useWorkbench\(\)/);
  assert.match(status, /useWorkbenchCase\(\)/);
  assert.doesNotMatch(status, /useWorkbench\(\)/);
  assert.match(navigator, /useWorkbenchLocation\(\)/);
  assert.match(navigator, /useWorkbenchLayout\(\)/);
});

test("case transitions, panel preferences and volatile terminal state remain separate modules", () => {
  const provider = source("state/workbench.tsx");
  assert.match(provider, /useNativeCaseSession\(/);
  assert.match(provider, /usePanelPreferences\(/);
  assert.match(provider, /useTerminalSessions\(/);
  assert.match(provider, /operationGeneration\.current/);
  assert.doesNotMatch(provider, /caseSessionSelectV1\(/);
  assert.doesNotMatch(provider, /window\.localStorage\.setItem\(STORAGE_KEY/);
});

test("heavy Jobs and Console views subscribe to separate update domains", () => {
  const jobs = source("components/shell/JobsDock.tsx");
  const consoleView = source("components/shell/ConsoleDock.tsx");
  assert.match(jobs, /useWorkbenchJobs\(\)/);
  assert.doesNotMatch(jobs, /useWorkbench\(\)/);
  assert.match(consoleView, /useWorkbenchTerminals\(\)/);
  assert.match(consoleView, /useWorkbenchCase\(\)/);
  assert.doesNotMatch(consoleView, /useWorkbench\(\)/);
});

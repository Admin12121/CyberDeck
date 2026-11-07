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

// --- unification contracts (2026-11-07 overhaul) ------------------------------

test("every workspace top row renders through WorkspaceShell — no bespoke chrome", () => {
  assert.match(source("design-system/compact.tsx"), /export function WorkspaceShell/);
  for (const file of views) {
    const text = fs.readFileSync(file, "utf8");
    // Pane headers legitimately carry the class inside the Pane primitive;
    // view files must not hand-roll the row themselves.
    assert.doesNotMatch(text, /className="[^"]*cd-workspace-toolbar/, file);
  }
});

test("tool surfaces never re-derive case readiness and never create cases", () => {
  assert.match(source("state/workbench.tsx"), /export function useCaseReady/);
  assert.match(source("state/workbench.tsx"), /export function useCreateCase/);
  assert.match(source("design-system/case-gate.tsx"), /export function CaseGate/);
  for (const file of views) {
    const text = fs.readFileSync(file, "utf8");
    assert.doesNotMatch(text, /caseSession\.phase === "ready"/, file);
    assert.doesNotMatch(text, /\bcaseCreate\(/, file);
    assert.doesNotMatch(text, /AuthorizedCaseAction/, file);
  }
  // Creation lives ONLY on the home page, through the shared helper.
  assert.match(source("app/_components/StartProject.tsx"), /useCreateCase\(\)/);
  // The status bar only reads case state out — no switcher, no create form.
  const status = source("components/shell/StatusBar.tsx");
  assert.doesNotMatch(status, /useCreateCase|caseCreate|<Select\b|\+ Case/);
  // The Cases page is manage-only: no create form; "New case" routes home.
  const casesView = source("app/cases/_components/CasesWorkspace.tsx");
  assert.doesNotMatch(casesView, /useCreateCase|Create saved case/);
  assert.match(casesView, /router\.push\("\/\?new=1"\)/);
});

test("the shared gate routes to the central case surfaces, not in-tool creation", () => {
  const gate = source("design-system/case-gate.tsx");
  assert.match(gate, /router\.push\("\/\?new=1"\)/);
  assert.match(gate, /router\.push\("\/cases"\)/);
  assert.doesNotMatch(gate, /caseCreate\(/);
  // All five web tabs render it; forensics intentionally uses a status chip.
  for (const file of [
    "app/web/_components/ProxyView.tsx",
    "app/web/_components/HistoryView.tsx",
    "app/web/_components/RepeaterView.tsx",
    "app/web/_components/ScannerView.tsx",
    "app/web/_components/SpiderView.tsx",
  ]) {
    assert.match(source(file), /<CaseGate\b/, file);
  }
});

test("views render shared primitives, not raw controls or arbitrary type sizes", () => {
  for (const file of views) {
    const text = fs.readFileSync(file, "utf8");
    assert.doesNotMatch(text, /<select[\s>]/, file);
    if (file.endsWith("RepeaterView.tsx") || file.endsWith("RecipesView.tsx")) {
      // Full-height code editors (request editor, recipe input) are the
      // sanctioned raw textareas; every bounded form field uses TextArea.
      assert.equal((text.match(/<textarea[\s>]/g) ?? []).length, 1, file);
    } else {
      assert.doesNotMatch(text, /<textarea[\s>]/, file);
    }
    assert.doesNotMatch(text, /accent-\[var\(--color-orange\)\]/, file);
    assert.doesNotMatch(text, /text-\[1[0-9]px\]/, file);
  }
});

test("the one error, progress, hex and findings treatments are the shared ones", () => {
  for (const name of ["ErrorStrip", "ProgressBar", "ResultStack", "HexRows", "ModeCard", "EmptyCard"]) {
    assert.match(source("design-system/compact.tsx"), new RegExp("export function " + name + "\\b"));
  }
  for (const name of ["TextArea", "NumberInput", "CheckBox"]) {
    assert.match(source("design-system/panes.tsx"), new RegExp("export function " + name + "\\b"));
  }
  // Category dispatchers share one keep-mounted component.
  assert.match(source("design-system/compact.tsx"), /export function CategoryWorkspace/);
  for (const dispatcher of [
    "app/crypto/_components/CryptoWorkspace.tsx",
    "app/network/_components/NetworkWorkspace.tsx",
    "app/forensics/_components/ForensicsWorkspace.tsx",
    "app/web/_components/WebWorkspace.tsx",
  ]) {
    const text = source(dispatcher);
    assert.match(text, /<CategoryWorkspace/, dispatcher);
    assert.doesNotMatch(text, /className=\{?\s*show\(/, dispatcher);
  }
});

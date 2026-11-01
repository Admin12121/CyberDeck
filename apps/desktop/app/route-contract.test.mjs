import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import path from "node:path";

const desktop = path.resolve(import.meta.dirname, "..");
const read = (name) => fs.readFileSync(path.join(desktop, name), "utf8");
const features = ["crypto", "network", "web", "forensics", "reverse"];

test("all feature routes own their components and have no obsolete feature tree", () => {
  assert.equal(fs.existsSync(path.join(desktop, "features")), false);
  for (const feature of features) {
    const route = `app/${feature}`;
    const page = read(`${route}/page.tsx`);
    assert.match(page, /from "\.\/_components"/);
    assert.doesNotMatch(page, /@features\/|@\/app\//);
    assert.equal(fs.existsSync(path.join(desktop, route, "_components", "index.ts")), true);
    assert.equal(fs.existsSync(path.join(desktop, route, "_components", feature[0].toUpperCase()+feature.slice(1)+"Workspace.tsx")), true);
  }
});

test("shared shell is persistent above pages and Home is route-local", () => {
  assert.match(read("app/layout.tsx"), /<AppShell>\{children\}<\/AppShell>/);
  assert.match(read("components/shell/AppShell.tsx"), /<WorkbenchProvider>/);
  assert.match(read("components/shell/AppShell.tsx"), /<WorkspaceSessionProvider>/);
  assert.match(read("components/shell/AppShell.tsx"), /<JobNotificationProvider>/);
  assert.match(read("app/page.tsx"), /from "\.\/_components"/);
  assert.equal(fs.existsSync(path.join(desktop, "components/shell/Home.tsx")), false);
});

test("coss ui primitives are installed and used in route-local Home", () => {
  const ui = path.join(desktop, "components/ui");
  assert.ok(fs.readdirSync(ui).filter((f) => f.endsWith(".tsx")).length >= 50);
  assert.match(read("app/_components/StartProject.tsx"), /from "@\/components\/ui\/button"/);
  assert.match(read("app/_components/StartProject.tsx"), /from "@\/components\/ui\/input"/);
  assert.match(read("app/_components/StartProject.tsx"), /Temporary workspace in memory/);
});

test("no retired features aliases remain in active frontend source", () => {
  const root = path.join(desktop, "app");
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const name = path.join(dir, entry.name);
      if (entry.isDirectory()) stack.push(name);
      else if (/\.(ts|tsx)$/.test(name)) assert.doesNotMatch(fs.readFileSync(name,"utf8"), /@features\//, name);
    }
  }
});

test("Home is centered, labels its three case modes, and shows only Save or Load actions", () => {
  const home = read("app/_components/StartProject.tsx");
  assert.match(home, /min-h-full items-center justify-center/);
  assert.match(home, /<img\s+src="\/logo.webp"/);
  assert.match(home, /<RadioGroup\b/);
  assert.match(home, /<Radio\b/);
  assert.match(home, /<Frame\b/);
  assert.match(home, /<FrameHeader\b/);
  assert.match(home, /<FramePanel\b/);
  assert.match(home, /<footer\b/);
  assert.ok(home.indexOf("<footer") > home.indexOf("<FramePanel"));
  assert.ok(home.indexOf("</footer>") < home.indexOf("</FramePanel>"));
  assert.match(home, /choice !== "temporary" &&/);
  assert.match(home, /choice === "new" \? "Save" : "Load"/);
  assert.doesNotMatch(home, />Skip<|>Next</);
});

test("shared workspace controls and case selection use installed coss primitives", () => {
  const panes = read("design-system/panes.tsx");
  const status = read("components/shell/StatusBar.tsx");
  const rail = read("components/shell/Rail.tsx");
  for (const name of ["button", "input", "select", "tabs"]) {
    assert.match(panes, new RegExp('from "@/components/ui/' + name + '"'));
  }
  assert.match(status, /<Select\b/);
  assert.doesNotMatch(status, /<select\b|<option\b/);
  assert.match(rail, /<Button\b/);
  assert.doesNotMatch(rail, /hover:bg-raised(?=")/);
  assert.match(rail, /<Link\s+href="\/"\s+aria-label="CyberDeck Home"/);
});

test("coss text fields and selects use restrained focus, not a global white outline", () => {
  const css = read("app/globals.css");
  const input = read("components/ui/input.tsx");
  const select = read("components/ui/select.tsx");
  assert.match(css, /:focus-visible:not\(\[data-slot\]\)/);
  assert.doesNotMatch(css, /(?<!:):focus-visible\s*\{\s*outline: 2px/);
  assert.match(input, /has-focus-visible:ring-\[1px\]/);
  assert.doesNotMatch(input, /has-focus-visible:ring-\[3px\]/);
  assert.match(select, /focus-visible:ring-\[1px\]/);
  assert.doesNotMatch(select, /focus-visible:ring-\[3px\]/);
});

test("Home hides jobs, terminal and footer without resetting background providers", () => {
  const shell = read("components/shell/AppShell.tsx");
  const rail = read("components/shell/Rail.tsx");
  assert.match(shell, /!home && ui\.dockOpen/);
  assert.match(shell, /!home && <StatusBar \/>/);
  assert.match(rail, /const home = pathname === "\/"/);
  assert.match(rail, /\{!home && <Button[\s\S]{0,260}setDockTab\("jobs"\)/);
  assert.match(rail, /\{!home && <Button[\s\S]{0,260}setDockTab\("console"\)/);
  assert.match(shell, /<JobNotificationProvider>/);
  assert.match(shell, /<WorkbenchProvider>/);
});

test("Home uses Frame > FrameHeader + FramePanel > footer with no bright border", () => {
  const home = read("app/_components/StartProject.tsx");
  const frame = read("components/ui/frame.tsx");
  assert.ok(frame.includes("relative rounded-xl bg-background bg-clip-padding p-5"));
  assert.ok(!frame.includes("relative rounded-xl border bg-background"));
  assert.ok(home.includes("<FrameHeader"));
  assert.ok(home.includes("<FramePanel"));
  assert.ok(home.includes("<footer"));
  assert.ok(home.indexOf("<footer") > home.indexOf("<FramePanel"));
  assert.ok(home.indexOf("</footer>") < home.indexOf("</FramePanel>"));
  assert.ok(!home.includes("FrameFooter"));
});

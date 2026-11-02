import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "../..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const palette = read("components/shell/CommandPalette.tsx");
const workbench = read("state/workbench.tsx");

test("palette uses coss Command, dialog, group, item, and keyboard hint primitives", () => {
  for (const tag of [
    "CommandDialog", "CommandDialogPopup", "Command", "CommandInput",
    "CommandPanel", "CommandEmpty", "CommandList", "CommandGroup",
    "CommandGroupLabel", "CommandCollection", "CommandItem",
    "CommandSeparator", "CommandFooter", "Kbd", "KbdGroup",
  ]) {
    assert.match(palette, new RegExp("<" + tag + "\\b"), tag);
  }
  assert.match(palette, /from "@\/components\/ui\/command"/);
  assert.match(palette, /from "@\/components\/ui\/kbd"/);
  assert.doesNotMatch(palette, /<dialog\b|<input\b|<kbd\b|role="listbox"|role="option"/);
  assert.doesNotMatch(palette, /activeIndex|scrollIntoView|showModal\(|addEventListener/);
});

test("palette preserves real categorized tools, disabled gating, and backend-aware actions", () => {
  assert.match(palette, /CATEGORIES\.map\(\(category\)/);
  assert.match(palette, /category\.tools\.filter\(\(tool\) => !tool\.disabled\)/);
  assert.match(palette, /wb\.selectTool\(tool\.id\)/);
  assert.match(palette, /wb\.setDockTab\("jobs"\)/);
  assert.match(palette, /wb\.setDockTab\("console"\)/);
  assert.match(palette, /run: wb\.toggleNavigator/);
  assert.match(palette, /wb\.setPaletteOpen\(false\)/);
  assert.doesNotMatch(palette, /Linear|Slack|Raycast|Create Snippet/);
});

test("global shortcuts remain owned by workbench: Ctrl/Cmd K palette, J jobs", () => {
  assert.match(workbench, /mod && e\.key\.toLowerCase\(\) === "k"/);
  assert.match(workbench, /setPaletteOpen\(\(v\) => !v\)/);
  assert.match(workbench, /mod && e\.key\.toLowerCase\(\) === "j"/);
  assert.match(workbench, /setDockTab\("jobs"\)/);
  assert.match(palette, /<CommandDialog open=\{wb\.paletteOpen\} onOpenChange=\{wb\.setPaletteOpen\}>/);
});

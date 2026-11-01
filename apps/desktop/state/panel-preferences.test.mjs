import assert from "node:assert/strict";
import { test } from "node:test";
import { PANEL_LIMITS, parsePanelSizes, clampPanel } from "./panel-preferences.ts";

test("invalid and missing stored preferences use safe defaults", () => {
  const expected = {
    navigator: PANEL_LIMITS.navigator.fallback,
    dock: PANEL_LIMITS.dock.fallback,
  };
  assert.deepEqual(parsePanelSizes(null), expected);
  assert.deepEqual(parsePanelSizes("{invalid"), expected);
  assert.deepEqual(parsePanelSizes('"oops"'), expected);
  assert.deepEqual(parsePanelSizes('{"navigator":"250","dock":null}'), expected);
});

test("panel sizes stay within established min and max", () => {
  assert.deepEqual(parsePanelSizes('{"navigator":1000,"dock":-1}'), {
    navigator: PANEL_LIMITS.navigator.max,
    dock: PANEL_LIMITS.dock.min,
  });
  assert.deepEqual(parsePanelSizes('{"navigator":205,"dock":400}'), {
    navigator: 205, dock: 400,
  });
  assert.equal(clampPanel(Number.NaN, 100, 300), 100);
  assert.equal(clampPanel(Number.POSITIVE_INFINITY, 100, 300), 100);
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { MAX_YARA_WINDOW_BYTES, yaraScanWindow } from "./yara-window.ts";

test("bounded YARA scan window follows verified evidence offset", () => {
  assert.deepEqual(yaraScanWindow(40, 0), { offset: 0, len: 40 });
  assert.deepEqual(yaraScanWindow(40, 39), { offset: 39, len: 1 });
  assert.deepEqual(yaraScanWindow(MAX_YARA_WINDOW_BYTES * 3, 75), { offset: 75, len: MAX_YARA_WINDOW_BYTES });
  assert.equal(yaraScanWindow(40, 40), null);
  assert.equal(yaraScanWindow(40, -1), null);
  assert.equal(yaraScanWindow(-1, 0), null);
  assert.equal(yaraScanWindow(0, 0), null);
  assert.equal(yaraScanWindow(Number.MAX_SAFE_INTEGER + 1, 0), null);
  assert.equal(yaraScanWindow(100, Number.NaN), null);
});

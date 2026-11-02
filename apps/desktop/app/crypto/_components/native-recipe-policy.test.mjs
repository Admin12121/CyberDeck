import { test } from "node:test";
import assert from "node:assert/strict";
import { canUseNativeRecipe } from "./native-recipe-policy.ts";

const native = new Set(["to_hex", "normalize_unicode", "unix_to_datetime", "datetime_to_unix"]);
const step = (opId) => ({ opId, enabled: true });

test("native route accepts ISO UTC and explicit timezone DateTime with one step", () => {
  for (const input of ["2026-11-02", "2026-11-02T06:15:00Z", "2026-11-02T12:00:00.123+05:45"]) {
    assert.ok(canUseNativeRecipe(input, [step("datetime_to_unix")], native), input);
  }
});

test("native route preserves TypeScript Date.parse for ambiguous dates and pipelines", () => {
  for (const input of ["October 31 2026", "2026-11-02T12:00:00", "2026/11/02", "2026-11-02T12:00:00z", "+010000-01-01", "2026-11-02T06:15Z"]) {
    assert.equal(canUseNativeRecipe(input, [step("datetime_to_unix")], native), false, input);
  }
  assert.equal(canUseNativeRecipe("2026-11-02", [step("to_hex"), step("datetime_to_unix")], native), false);
  assert.equal(canUseNativeRecipe("2026-11-02", [step("normalize_unicode"), step("datetime_to_unix")], native), false);
  assert.equal(canUseNativeRecipe("2026-11-02", [step("datetime_to_unix"), step("datetime_to_unix")], native), false);
});

test("native route is byte-input agnostic for non-date recipes, enabled steps only", () => {
  assert.ok(canUseNativeRecipe("⚠️ arbitrary", [step("normalize_unicode"), step("to_hex")], native));
  assert.ok(canUseNativeRecipe("text", [{ opId: "non_native", enabled: false }, step("to_hex")], native));
  assert.equal(canUseNativeRecipe("text", [step("non_native")], native), false);
});

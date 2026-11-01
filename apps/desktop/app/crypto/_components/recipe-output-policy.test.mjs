import { test } from "node:test";
import assert from "node:assert/strict";
import { outputCapabilities, recipeResultIdentity } from "./recipe-output-policy.ts";

const value = (bytes, error) => ({ outputBytes: Uint8Array.from(bytes), error });

test("empty and errored results do not enable output actions", () => {
  for (const result of [null, value([]), value([65], { message: "failed" })]) {
    for (const mode of ["text", "hex", "image"]) {
      const available = outputCapabilities(result, mode, "image/png", true);
      assert.equal(available.hasBytes, false);
      assert.equal(available.canDownload, false);
      assert.equal(available.canCopy, false);
      assert.equal(available.canImage, false);
    }
  }
});

test("valid UTF-8 text supports text, hex, download and matching copy", () => {
  const result = value([72, 101, 108, 108, 111]);
  assert.deepEqual(outputCapabilities(result, "text", null), {
    hasBytes: true, canText: true, canHex: true, canImage: false, canDownload: true, canCopy: true,
  });
  assert.equal(outputCapabilities(result, "hex", null).canCopy, true);
  assert.equal(outputCapabilities(result, "image", null).canCopy, false);
});

test("arbitrary binary bytes use hex/file, not replacement-character text", () => {
  const result = value([0xff, 0xfe, 0x00]);
  const available = outputCapabilities(result, "text", null);
  assert.equal(available.canText, false);
  assert.equal(available.canHex, true);
  assert.equal(available.canImage, false);
  assert.equal(available.canDownload, true);
  assert.equal(available.canCopy, false);
  assert.equal(outputCapabilities(result, "hex", null).canCopy, true);
});

test("recognized image is previewable; PNG clipboard is feature-gated", () => {
  const result = value([137, 80, 78, 71, 13, 10, 26, 10]);
  assert.equal(outputCapabilities(result, "image", "image/png").canImage, true);
  assert.equal(outputCapabilities(result, "image", "image/png", false).canCopy, false);
  assert.equal(outputCapabilities(result, "image", "image/png", true).canCopy, true);
  assert.equal(outputCapabilities(result, "image", "image/jpeg", true).canCopy, false);
  assert.equal(outputCapabilities(result, "hex", "image/png").canCopy, true);
});

test("manual bake outputs are invalidated when case, input or steps change", () => {
  const base = recipeResultIdentity("case-a", "abc", [{ opId: "to_hex", enabled: true }]);
  assert.notEqual(base, recipeResultIdentity("case-b", "abc", [{ opId: "to_hex", enabled: true }]));
  assert.notEqual(base, recipeResultIdentity("case-a", "abcd", [{ opId: "to_hex", enabled: true }]));
  assert.notEqual(base, recipeResultIdentity("case-a", "abc", [{ opId: "to_base64", enabled: true }]));
  assert.equal(base, recipeResultIdentity("case-a", "abc", [{ opId: "to_hex", enabled: true }]));
});

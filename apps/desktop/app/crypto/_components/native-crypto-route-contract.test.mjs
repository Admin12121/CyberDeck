import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve, dirname } from "node:path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../..");
const read = (path) => readFileSync(resolve(root, path), "utf8");

test("Crypto Recipes native allowlist tracks every actual Rust native operation", () => {
  const rust = read("crates/crypto/src/recipes.rs");
  const ui = read("apps/desktop/app/crypto/_components/RecipesView.tsx");
  const rustNative = rust.match(/pub fn native_operation\(id: &str\) -> bool \{([\s\S]*?)\n\}/)?.[1];
  const uiNative = ui.match(/const NATIVE_RECIPE_OPS = new Set\(\[([\s\S]*?)\]\)/)?.[1];
  assert.ok(rustNative, "Rust native-operation catalog not found");
  assert.ok(uiNative, "frontend native-operation allowlist not found");
  const ids = (str) => Array.from(str.matchAll(/"([a-z][a-z0-9_]*)"/g), (item) => item[1]).sort();
  assert.deepEqual(ids(uiNative), ids(rustNative));
  assert.equal(ids(rustNative).length, 41);
});

test("Recovery V1 real route uses existing typed native calls and authorized reveal", () => {
  const ipc = read("apps/desktop/lib/ipc.ts");
  const rust = read("apps/desktop/src-tauri/src/features/crypto/ipc/recovery.rs");
  const ui = read("apps/desktop/app/crypto/_components/NativeRecoveryV1.tsx");
  const view = read("apps/desktop/app/crypto/_components/HashAnalysisView.tsx");
  for (const [name, command] of [
    ["recoveryDevicesV1", "recovery_devices_v1"],
    ["recoveryStartV1", "recovery_start_v1"],
    ["recoveryCancelV1", "recovery_cancel_v1"],
    ["recoveryStatusV1", "recovery_status_v1"],
    ["recoveryDiscardV1", "recovery_discard_v1"],
    ["recoveryRevealV1", "recovery_reveal_v1"],
  ]) {
    assert.match(ipc, new RegExp("function " + name + "\\("));
    assert.match(ipc, new RegExp('invoke<[^>]*>\\("' + command + '"'));
    assert.match(rust, new RegExp("pub (?:async )?fn " + command + "\\("));
    assert.match(ui, new RegExp("\\b" + name + "\\b"));
  }
  assert.match(ui, /caseSession\.phase === "ready"/);
  assert.match(ui, /caseSession\.revision/);
  assert.match(ui, /status\?\.reveal_available/);
  assert.match(ui, /window\.setTimeout\(clearReveal, 30000\)/);
  assert.match(ui, /currentJob.*scope/);
  assert.doesNotMatch(ui, /localStorage|sessionStorage|crackHistory/);
  assert.match(view, /<NativeRecoveryV1 targetHash=\{input\}/);
  assert.match(view, /const \[legacyRecoveryEnabled\] = useState\(false\)/);
});

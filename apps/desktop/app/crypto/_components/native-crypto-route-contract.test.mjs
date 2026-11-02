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
  assert.equal(ids(rustNative).length, 59);
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
  assert.doesNotMatch(view, /CrackedHistory|legacyRecoveryEnabled|crackHistoryList|crackHistoryClear/);
  assert.match(view, /<NativeRecoveryResults \/>/);
  assert.match(view, /<NativeRecoveryControls \/>/);
  assert.match(view, /title="Detected Candidates"/);
  assert.match(view, /title="Recovery Results"/);
  assert.ok(ui.includes("onClick={() => void r.start()}"));
  assert.ok(ui.includes("onClick={() => void r.cancel()}"));
  assert.ok(ui.includes("onClick={() => void r.discard()}"));
  assert.ok(ui.includes('r.status === null ? ('));
  assert.ok(ui.includes('r.running ? ('));
  assert.ok(ui.includes('aria-label={r.choosingWordlist ? "Selecting wordlist" : "Choose wordlist"}'));
  assert.ok(ui.includes('aria-label={r.busy ? "Starting recovery" : "Start recovery"}'));
  assert.ok(ui.includes('onClick={() => void r.chooseWordlist()}'));
  assert.ok(ui.includes('disabled={!r.desktop || !r.scope'));
  for (const [name, command] of [
    ["recoverySelectWordlistV1", "recovery_select_wordlist_v1"],
    ["recoveryWordlistStatusV1", "recovery_wordlist_status_v1"],
  ]) {
    assert.ok(ipc.includes("function " + name + "("));
    assert.ok(ipc.includes('"' + command + '"'));
    assert.ok(rust.includes("fn " + command + "("));
    assert.ok(ui.includes(name));
  }
  assert.ok(read("apps/desktop/src-tauri/src/main.rs").includes("recovery_select_wordlist_v1"));
  assert.ok(view.includes("maxLength={MAX_HASH_INPUT_CHARS}"));
  assert.ok(view.includes("resize-none"));
  assert.ok(view.includes("showNextCandidates(event.currentTarget)"));
  assert.ok(ui.includes("Scroll to view more masked matches"));
  assert.ok(ui.includes('<AccordionItem value="advanced"'));
  assert.ok(ui.includes('<Accordion defaultValue={[]}'));
  assert.ok(ui.includes('Advanced settings'));
  assert.ok(ui.includes('from "@/components/ui/accordion"'));
  assert.ok(ui.includes('from "@lucasmarkes/hairline/react"'));
  assert.ok(ui.includes('<Phosphor intensity={1} play'));
  assert.ok(ui.includes('Wordlist and recovery actions'));
  assert.ok(ui.includes('size="icon"'));
  assert.ok(ui.includes('role="group" aria-label="Wordlist and recovery actions"'));
  assert.ok(ui.includes('onClick={() => void r.chooseWordlist()}'));
  assert.ok(ui.includes('onClick={() => void r.start()}'));
  assert.ok(ui.includes('onClick={() => void r.cancel()}'));
  assert.ok(ui.includes('onClick={() => void r.discard()}'));
  assert.ok(ui.includes('value: "auto"'));
  assert.ok(ui.includes('r.selection.backend === "cpu"'));
  const combo = read("apps/desktop/app/crypto/_components/VerifyAlgorithmCombobox.tsx");
  assert.ok(combo.includes('from "@/components/ui/combobox"'));
  assert.ok(combo.includes("<ComboboxCollection>"));
  assert.ok(combo.includes("Search verification algorithms"));
  const catalog = read("crates/crypto/src/lib.rs");
  const verifiedAlgorithms = ["md4", "md5", "ntlm", "sha1", "sha224", "sha256",
    "sha384", "sha512", "sha3_256", "sha3_512", "crc32"];
  for (const id of verifiedAlgorithms) {
    assert.ok(combo.includes('id: "' + id + '"'), "Verify must offer native " + id);
    assert.ok(catalog.includes('op("' + id + '"'), "Verify should not offer unimplemented " + id);
  }
  assert.ok(view.includes('<Accordion defaultValue={[]}'));
  assert.ok(view.includes('value="verify"'));
  assert.ok(view.includes('VerifyAlgorithmCombobox'));
  assert.ok(view.includes('hashDrafts = new Map'));
  assert.ok(view.includes('keepHash(caseId, value)'));
  assert.ok(view.includes('file.size > 8192'));
  assert.ok(view.includes('setHashImportError'));
  assert.ok(!view.includes("hashDrafts.set(caseId, candidate)"));

});

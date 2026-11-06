// Source-contract tests for the saved scan-profiles + timing-template slice.
// ScanView.tsx is a React client component, so under plain `node --test` it is
// asserted as SOURCE TEXT: the controls, the honesty tooltip and the load/save
// handlers must exist verbatim. The Rust backend file is cross-checked for
// command names, bounds and validation, and the declared registries are
// extracted and evaluated for real assertions.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const scanViewSource = readFileSync(join(here, "ScanView.tsx"), "utf8");
const canonicalIpcSource = readFileSync(join(here, "../../../lib/ipc.ts"), "utf8");
const scanProfilesSource = readFileSync(
  join(here, "../../../src-tauri/src/features/network/ipc/scan_profiles.rs"),
  "utf8",
);

test("timing template selector declares exactly the five documented templates", () => {
  const match = /const TIMING_TEMPLATES[^=]*= (\[[^\]]*\]);/.exec(scanViewSource);
  assert.ok(match, "TIMING_TEMPLATES registry missing from ScanView.tsx");
  // Evaluate the extracted literal: it contains only string/object literals,
  // so a Function evaluation of our own source is deterministic and safe here.
  const registry = new Function("return " + match[1])();
  assert.deepEqual(
    registry.map((entry) => entry.value),
    ["paranoid", "sneaky", "polite", "normal", "aggressive"],
  );
  for (const entry of registry) {
    assert.equal(typeof entry.label, "string");
    assert.ok(entry.label.length > 0);
  }
});

test("the timing selector is honest: only Normal is adaptive today", () => {
  assert.match(scanViewSource, /Only Normal is adaptive today/);
  assert.match(scanViewSource, /EWMA of measured probe durations/);
  assert.match(scanViewSource, /TCP 300-1800 ms \/ UDP 300-1200 ms/);
  // The tooltip must disclose that the other labels change no behavior yet.
  assert.match(scanViewSource, /Selecting them changes no probe behavior today/);
  assert.match(scanViewSource, /ariaLabel="Timing template"/);
});

test("profile controls exist with picker, name input, save, load and delete", () => {
  assert.match(scanViewSource, /ariaLabel="Saved scan profile"/);
  // UX revision: save/load/delete are icon toolbar buttons whose full labels
  // (and honesty wording) live in the tooltip/aria-label; the profile-name
  // input is revealed only while saving and hides again after a save.
  assert.match(scanViewSource, /icon=\{Save\}/);
  assert.match(scanViewSource, /title="Save profile — /);
  assert.match(scanViewSource, /icon=\{Upload\}/);
  assert.match(scanViewSource, /title="Load profile — /);
  assert.match(scanViewSource, /icon=\{Trash2\}/);
  assert.match(scanViewSource, /title="Delete profile — /);
  assert.match(scanViewSource, /ariaLabel="New profile name"/);
  assert.match(scanViewSource, /savingProfile/);
  assert.match(scanViewSource, /\{profiles\.length\}\/32 profiles/);
  // The picker degrades to an explicit empty entry, never a blank select.
  assert.match(scanViewSource, /No profile selected/);
});

test("save, load and delete handlers are bounded and validate stored JSON", () => {
  const saveBody = /const saveProfile = async \(\) => \{([\s\S]*?)\n  \};/.exec(scanViewSource);
  assert.ok(saveBody, "saveProfile handler missing");
  assert.match(saveBody[1], /!desktop \|\| profileBusy \|\| !name \|\| !target\.trim\(\)/);
  assert.match(saveBody[1], /netscanProfileSaveV1\(name, JSON\.stringify\(/);
  // A profile pins exactly the four scan parameters.
  assert.match(saveBody[1], /target, ports, transport, timing/);
  const loadBody = /const loadSelectedProfile = \(\) => \{([\s\S]*?)\n  \};/.exec(scanViewSource);
  assert.ok(loadBody, "loadSelectedProfile handler missing");
  assert.match(loadBody[1], /JSON\.parse\(profile\.params_json\)/);
  // Every stored field is type-checked before it reaches the form state.
  assert.match(loadBody[1], /typeof params\.target === "string"/);
  assert.match(loadBody[1], /params\.transport === "udp" \|\| params\.transport === "tcp"/);
  assert.match(loadBody[1], /TIMING_TEMPLATES\.some\(\(t\) => t\.value === params\.timing\)/);
  assert.match(loadBody[1], /profile not loaded/);
  const deleteBody = /const deleteSelectedProfile = async \(\) => \{([\s\S]*?)\n  \};/.exec(scanViewSource);
  assert.ok(deleteBody, "deleteSelectedProfile handler missing");
  assert.match(deleteBody[1], /netscanProfileDeleteV1\(selectedProfile\)/);
});

test("frontend clients target the registered scan-profile command names", () => {
  for (const command of [
    "netscan_profile_save_v1",
    "netscan_profile_list_v1",
    "netscan_profile_delete_v1",
  ]) {
    assert.match(canonicalIpcSource, new RegExp("[\"']" + command + "[\"']"));
    assert.match(
      scanProfilesSource,
      new RegExp("pub fn " + command),
      command + " not defined in scan_profiles.rs",
    );
  }
});

test("backend profiles are bounded session-local presets, never case evidence", () => {
  assert.match(scanProfilesSource, /pub const MAX_PROFILES: usize = 32/);
  assert.match(scanProfilesSource, /pub const MAX_PARAMS_JSON_BYTES: usize = 4096/);
  assert.match(scanProfilesSource, /pub const MAX_NAME_LEN: usize = 64/);
  // Safe name charset: no path separators, control bytes or markup.
  assert.match(scanProfilesSource, /is_ascii_alphanumeric\(\) \|\| matches!\(c, ' ' \| '-' \| '_' \| '\.'\)/);
  // The parameter envelope must be a JSON object and size-capped.
  assert.match(scanProfilesSource, /profile parameters must be a JSON object/);
  assert.match(scanProfilesSource, /profile parameters exceed \{MAX_PARAMS_JSON_BYTES\} bytes/);
  // The cap refuses instead of silently evicting a user's presets.
  assert.match(scanProfilesSource, /profile limit of \{MAX_PROFILES\} reached/);
  // No evidence-store dependency: profiles are UI convenience state.
  assert.ok(
    !/EvidenceCtx/.test(scanProfilesSource),
    "scan_profiles.rs must not depend on the case evidence store",
  );
});

test("profile saving requires no network authorization because it transmits nothing", () => {
  assert.match(scanViewSource, /never touches the network/);
  assert.match(scanViewSource, /no authorization is required/);
  assert.match(scanProfilesSource, /never touch the evidence store/);
});

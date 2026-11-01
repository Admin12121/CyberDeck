import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const dir = dirname(fileURLToPath(import.meta.url));
const read = (part) => readFileSync(join(dir, part), "utf8");
const page = read("page.tsx");
const view = read("_components/CasesWorkspace.tsx");
const ipc = read("_components/native.ts");
const scoped = read("../../src-tauri/src/features/cases/ipc/scoped.rs");

test("Cases is a route-local coss workspace, not a duplicate global shell", () => {
  assert.match(page, /CasesWorkspace/);
  for (const component of ["button", "input", "frame", "tabs", "table"]) {
    assert.match(view, new RegExp('from "@/components/ui/' + component + '"'));
  }
  assert.match(view, /cd-workspace-toolbar/);
  assert.doesNotMatch(view, /@features\/|@\/features\/|FrameFooter/);
});

test("Cases read commands rely on backend-selected identity and never trust client file paths", () => {
  for (const name of ["case_resume_scoped_v1", "case_evidence_review_scoped_v1",
                      "case_integrity_scoped_v1", "case_artifact_reference_scoped_v1"]) {
    assert.match(ipc, new RegExp(name));
    assert.match(scoped, new RegExp("fn " + name));
  }
  assert.match(scoped, /session\.selected\(\)/);
  assert.match(scoped, /session\.ensure\(&scope\)/);
  assert.doesNotMatch(ipc, /stored_path|dataB64|rawBytes|password/);
});

test("cross-case copy requires native operator confirmation and selected-case publication", () => {
  assert.match(ipc, /case_copy_artifact_to_existing_v1/);
  assert.match(scoped, /MessageDialogButtons::YesNo/);
  assert.match(scoped, /with_current_publication/);
  assert.match(view, /copySelectedArtifactToExisting/);
  assert.match(view, /Original|original/);
  assert.doesNotMatch(ipc, /reveal:\s*true|authorized:\s*true/);
});

test("uncertain orphan evidence remains visibly read-only and temporary workspace is not claimed saved", () => {
  assert.match(view, /Incomplete scan/);
  assert.match(view, /indexed_tampered/);
  assert.match(view, /never silently adopted or deleted/);
  assert.match(view, /Temporary Quick Tools/);
  assert.doesNotMatch(view, /localStorage\.setItem|sessionStorage\.setItem/);
});

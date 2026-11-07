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
  // House style: the same primitives every tool view uses — coss button/
  // input/frame plus the shared design-system shell, tabs and data-table.
  // No separate tab/table systems, no bespoke top row.
  for (const component of ["button", "input", "frame"]) {
    assert.match(view, new RegExp('from "@/components/ui/' + component + '"'));
  }
  assert.match(view, /from "@ds\/compact"/);
  assert.match(view, /<WorkspaceShell/);
  assert.match(view, /from "@ds\/panes"/);
  assert.match(view, /WorkspaceTabs/);
  assert.match(view, /data-table/);
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

test("temporary Quick Tools UI is wired to backend-owned volatile staging and explicitly confirmed atomic promotion", () => {
  const native = read("_components/native.ts");
  const rust = read("../../src-tauri/src/features/cases/ipc/temporary.rs");
  for (const name of ["case_temp_stage_sha256_v1", "case_temp_overview_v1", "case_temp_discard_v1", "case_temp_promote_v1"]) {
    assert.match(native, new RegExp(name));
    assert.match(rust, new RegExp("fn " + name));
  }
  assert.match(view, /Save Current Work as Case/);
  assert.match(view, /stageTemporarySha256/);
  assert.match(view, /promoteTemporary/);
  assert.match(view, /original input/i);
  assert.match(rust, /MessageDialogButtons::YesNo/);
  assert.match(rust, /with_current_publication/);
  assert.doesNotMatch(native, /localStorage|stored_path|dataB64|privateKey/);
});

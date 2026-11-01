import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

test("native YARA subset command has exactly one handler registration and a real feature-local call", () => {
  const main = source("../../../src-tauri/src/main.rs");
  const wire = source("./yara-subset.ts");
  const panel = source("./YaraSubsetPanel.tsx");
  assert.equal((main.match(/features::forensics::ipc::evidence::file_yara_subset_scan/g) ?? []).length, 1);
  assert.match(wire, /invoke<YaraSubsetResponse>\("file_yara_subset_scan"/);
  assert.match(wire, /caseId, id: artifactId, offset, len, ruleSource/);
  assert.match(panel, /fileYaraSubsetScan\(caseId, artifactId, window\.offset, window\.len, rule\)/);
  assert.match(panel, /generation\.current/);
  assert.match(panel, /integrity_checked/);
});

test("real Forensics route consumes metadata, case evidence, carving and derived records", () => {
  const files = source("./FileAnalysisView.tsx");
  const metadata = source("./MetadataView.tsx");
  const shared = source("./shared.tsx");
  const workspace = source("./ForensicsWorkspace.tsx");
  assert.match(workspace, /<EvidenceProvider key={caseId}>/);
  assert.match(files, /fileCarvePreview\(wb\.caseId, artifact\.id, offset, len\)/);
  assert.match(files, /PNG \/ RIFF-WAVE \/ JPEG \/ GIF \/ U-Boot uImage candidates/);
  assert.match(files, /extractedRecords\.slice\(0, 128\)/);
  assert.match(metadata, /fileMetadataScan\(wb\.caseId, artifact\.id\)/);
  assert.match(metadata, /availableMetadataGroups/);
  assert.match(metadata, /wb\.selectTool\("forensics\.files"\)/);
  assert.match(shared, /await fileList\(caseId\)/);
  assert.match(shared, /fileImportDialog\(caseId\)/);
  assert.match(shared, /setQuery\(""\)/);
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { compatibleArtifactTargets } from "./artifact-workflows.ts";
const file = { caseId: "case-a", artifactId: "artifact-1", kind: "file" };
const consumers = [
  { toolId: "crypto.recipes", accepts: ["bytes", "text"], actions: ["decode"] },
  { toolId: "forensics.files", accepts: ["file"], actions: ["open"] },
];
test("only type-compatible declared tool consumers appear", () => {
  assert.deepEqual(compatibleArtifactTargets(file, "case-a", consumers).map(x=>x.toolId), ["forensics.files"]);
});
test("cross-case, unsaved, and unknown artifact references do not transfer", () => {
  assert.deepEqual(compatibleArtifactTargets(file, "case-b", consumers), []);
  assert.deepEqual(compatibleArtifactTargets({ ...file, artifactId: "" }, "case-a", consumers), []);
  assert.deepEqual(compatibleArtifactTargets({ ...file, caseId: "scratchpad" }, "scratchpad", consumers), []);
});

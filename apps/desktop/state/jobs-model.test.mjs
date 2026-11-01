import assert from "node:assert/strict";
import { test } from "node:test";
import { applyJobEvent, completeLocalJob } from "./jobs-model.ts";

const active = {
  [-1]: { id: -1, kind: "analysis", status: "running", percent: 0, message: "Working", startedAt: 100 },
};

test("local job completion preserves the original record", () => {
  const done = completeLocalJob(active, -1, "completed", "Completed", 200);
  assert.equal(done[-1].status, "completed");
  assert.equal(done[-1].percent, 100);
  assert.equal(done[-1].startedAt, 100);
  assert.equal(done[-1].finishedAt, 200);
  assert.equal(active[-1].status, "running");
});

test("cleared case jobs cannot be recreated by an old completion", () => {
  const cleared = {};
  assert.equal(completeLocalJob(cleared, -1, "failed", "late", 200), cleared);
  assert.deepEqual(Object.keys(completeLocalJob(cleared, -1, "completed", "late", 200)), []);
});

test("late completion cannot overwrite an already finalized local job", () => {
  const done = completeLocalJob(active, -1, "completed", "Completed", 200);
  assert.equal(completeLocalJob(done, -1, "failed", "late", 300), done);
});

test("job progress for unknown native jobs does not create phantom records", () => {
  const unknown = applyJobEvent({}, { type: "progress", job_id: 55, step: 1, percent: 80, message: "late" }, "scanner", 20);
  assert.deepEqual(unknown, {});
});

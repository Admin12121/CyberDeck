import test from "node:test";
import assert from "node:assert/strict";
import { hasCurrentRecoveryScope, isSha256WordlistTarget, recoveryDisplay } from "./recovery-presentation.ts";

const makeStatus = (phase, matches = [], reveal_available = false) => ({
  job_id: 3, phase, progress: null,
  summary: phase === "completed" ? {
    algorithm: "sha256", backend: { backend: "cpu" },
    engine: "native", tried: 42, cancelled: false,
    limit_reached: false, duration_ms: 10, matches,
  } : null,
  error: phase === "failed" ? "native failure" : null, reveal_available,
});

test("Recovery V1 accepts only 64 hex character targets", () => {
  assert.equal(isSha256WordlistTarget("a".repeat(64)), true);
  assert.equal(isSha256WordlistTarget(" A".repeat(32)), false);
  assert.equal(isSha256WordlistTarget("a".repeat(32)), false, "MD5-like input must not be eligible");
  assert.equal(isSha256WordlistTarget("z".repeat(64)), false);
  assert.equal(isSha256WordlistTarget("$y$something"), false);
  assert.equal(isSha256WordlistTarget(""), false);
});

test("Results have distinct idle, case required, running and cancelling presentations", () => {
  assert.equal(recoveryDisplay(null, null, null, null).kind, "case");
  assert.equal(recoveryDisplay("case:1", null, null, null).kind, "empty");
  assert.equal(recoveryDisplay("case:1", 3, null, null).kind, "loading");
  assert.equal(recoveryDisplay("case:1", 3, makeStatus("running"), null).kind, "running");
  assert.equal(recoveryDisplay("case:1", 3, makeStatus("cancelling"), null).title, "Cancelling recovery");
});

test("Completed results stay masked and expired results are distinct", () => {
  const matches = [{ candidate_index: 9, masked: true }];
  assert.equal(recoveryDisplay("case:1", 3, makeStatus("completed", matches, true), null).kind, "completed");
  assert.equal(recoveryDisplay("case:1", 3, makeStatus("completed", [], false), null).kind, "no-match");
  assert.equal(recoveryDisplay("case:1", 3, makeStatus("completed", matches, false), null).kind, "expired");
});

test("Cancellation, failure and revoked missing jobs have distinct states", () => {
  assert.equal(recoveryDisplay("case:1", 3, makeStatus("cancelled"), null).kind, "cancelled");
  assert.equal(recoveryDisplay("case:1", 3, makeStatus("failed"), null).kind, "failed");
  assert.equal(recoveryDisplay("case:1", null, null, "Result expired or revoked").kind, "expired");
});

test("Discard is distinguishable from initial empty state", () => {
  assert.equal(recoveryDisplay("case:1", null, null, null, true).kind, "discarded");
  assert.equal(recoveryDisplay("case:1", null, null, null, false).kind, "empty");
});

test("Case or backend job switch masks any stale result before effect cleanup", () => {
  const previous = { scope: "case-a:8", id: 42 };
  assert.equal(hasCurrentRecoveryScope(previous, "case-a:8", 42), true);
  assert.equal(hasCurrentRecoveryScope(previous, "case-a:9", 42), false);
  assert.equal(hasCurrentRecoveryScope(previous, "case-b:8", 42), false);
  assert.equal(hasCurrentRecoveryScope(previous, null, 42), false);
  assert.equal(hasCurrentRecoveryScope(previous, "case-a:8", 43), false);
  assert.equal(hasCurrentRecoveryScope(null, "case-a:8", 42), false);
});

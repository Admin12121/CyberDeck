import assert from "node:assert/strict";
import { test } from "node:test";
import { createCaseTransitionController } from "./case-transition.ts";

const defer = () => {
  let resolve;
  let reject;
  const promise = new Promise((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, resolve, reject };
};

test("rapid case A → B → A transitions remain serialized and reject stale results", async () => {
  const pending = [], published = [], started = [];
  const coordinator = createCaseTransitionController((id) => {
    const request = defer();
    pending.push(request);
    started.push(id);
    return request.promise;
  }, (value) => published.push(value));

  coordinator.change("case-a", true);
  await Promise.resolve(); // begin A
  assert.deepEqual(started, ["case-a"]);
  coordinator.change("case-b", true);
  coordinator.change("case-a", true);
  pending[0].resolve({ case_id: "case-a", revision: 1 });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(started.length, 2);
  assert.equal(started[1], "case-a");
  pending[1].resolve({ case_id: "case-a", revision: 3 });
  await coordinator.settled();
  assert.equal(published.at(-1).phase, "ready");
  assert.equal(published.at(-1).revision, 3);
  assert.equal(published.filter((state) => state.phase === "ready").length, 1);
});

test("late rejection and unmount invalidation cannot publish a new ready/error state", async () => {
  const pending = defer();
  const published = [];
  const coordinator = createCaseTransitionController(() => pending.promise, (state) => published.push(state));
  coordinator.change("case-a", true);
  await Promise.resolve();
  coordinator.invalidate();
  pending.reject(new Error("old transport error"));
  await coordinator.settled();
  assert.deepEqual(published.map((state) => state.phase), ["selecting"]);
});

test("backend case mismatch rejects case selection", async () => {
  const published = [];
  const coordinator = createCaseTransitionController(async () => ({ case_id: "other", revision: 1 }), (value) => published.push(value));
  coordinator.change("case-a", true);
  await coordinator.settled();
  assert.equal(published.at(-1).phase, "error");
  assert.match(published.at(-1).error, /different case/);
});

test("scratchpad clears backend selection and browser fallback never calls native", async () => {
  const visited = [], published = [];
  const coordinator = createCaseTransitionController(async (id) => {
    visited.push(id);
    return { case_id: id, revision: 5 };
  }, (value) => published.push(value));
  coordinator.change("scratchpad", true);
  await coordinator.settled();
  assert.deepEqual(visited, [null]);
  assert.equal(published.at(-1).phase, "idle");
  coordinator.change("case-b", false);
  await coordinator.settled();
  assert.equal(published.at(-1).phase, "unavailable");
  assert.deepEqual(visited, [null]);
});

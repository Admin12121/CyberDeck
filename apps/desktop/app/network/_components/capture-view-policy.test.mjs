import test from "node:test";
import assert from "node:assert/strict";
import { captureLimits, activeCaptureId, matchesCaptureIdentity, boundedPageOffset, captureInterfaceEligible } from "./capture-view-policy.ts";

test("native capture limits enforce wire bounds without floating-point coercion", () => {
  assert.deepEqual(captureLimits("4000", "8", "60"), {
    max_packets: 4000, max_bytes: 8 * 1024 * 1024, duration_ms: 60_000,
  });
  assert.deepEqual(captureLimits("20000", "16", "600"), {
    max_packets: 20000, max_bytes: 16 * 1024 * 1024, duration_ms: 600_000,
  });
  for (const values of [
    ["0","8","60"],["20001","8","60"],["1","0","60"],["1","17","60"],
    ["1","8","0"],["1","8","601"],["1.5","8","60"],["-1","8","60"],
    ["oops","8","60"],["Infinity","8","60"],
  ]) assert.equal(captureLimits(...values), null);
});

test("backend session reference is volatile and revision-scoped", () => {
  assert.equal(activeCaptureId({ id: 21, revision: 5 }, 5), 21);
  assert.equal(activeCaptureId({ id: 21, revision: 5 }, 6), null);
  assert.equal(activeCaptureId({ id: 21, revision: 5 }, null), null);
  assert.equal(activeCaptureId(null, 5), null);
  assert.equal(activeCaptureId({ id: -1, revision: 5 }, 5), null);
  assert.equal(matchesCaptureIdentity({ session_id: 21, case_id: "case-a" }, 21, "case-a"), true);
  assert.equal(matchesCaptureIdentity({ session_id: 21, case_id: "case-a" }, 21, "case-b"), false);
  assert.equal(matchesCaptureIdentity({ session_id: 22, case_id: "case-a" }, 21, "case-a"), false);
});

test("pagination cannot request negative or out-of-bounds pages", () => {
  assert.equal(boundedPageOffset(0, 240, 1), 100);
  assert.equal(boundedPageOffset(100, 240, 1), 200);
  assert.equal(boundedPageOffset(200, 240, 1), null);
  assert.equal(boundedPageOffset(0, 240, -1), null);
  assert.equal(boundedPageOffset(200, 240, -1), 100);
  assert.equal(boundedPageOffset(0, 0, 1), null);
  assert.equal(boundedPageOffset(0, 100, 1, 300), null);
});

test("discovered Windows interface is not capture ready without a compatible CyberDeck driver", () => {
  const nic = { up: true, ethernet: true, loopback: false };
  assert.equal(captureInterfaceEligible({ ...nic, capture_supported: false }), false);
  assert.equal(captureInterfaceEligible({ ...nic, capture_supported: true }), true);
  assert.equal(captureInterfaceEligible({ ...nic }), true); // existing Linux wire compatibility
  assert.equal(captureInterfaceEligible({ ...nic, up: false }), false);
  assert.equal(captureInterfaceEligible({ ...nic, loopback: true }), false);
  assert.equal(captureInterfaceEligible({ ...nic, ethernet: false }), false);
});

import test from "node:test";
import assert from "node:assert/strict";
import {
  sessionKey, rememberNativeSession, currentNativeSession,
  dropNativeSession, subscribeNativeSessions,
} from "./capture-session-registry.ts";

test("route remount recovers only the active revision's backend-owned session reference", () => {
  const first = sessionKey("case-one", 9);
  const later = sessionKey("case-one", 10);
  rememberNativeSession(first, 17);
  assert.equal(currentNativeSession(first), 17);
  assert.equal(currentNativeSession(later), null);
  assert.equal(currentNativeSession(sessionKey("case-two", 9)), null);
  rememberNativeSession(later, 18);
  assert.equal(currentNativeSession(later), 18);
  dropNativeSession(first);
  dropNativeSession(later);
});

test("session starting after source view unmount still wakes a remounted view", () => {
  const key = sessionKey("capture-case", 55);
  let changes = 0;
  const stopListening = subscribeNativeSessions(() => { changes++; });
  rememberNativeSession(key, 300);
  assert.equal(changes, 1);
  stopListening();
  rememberNativeSession(key, 301);
  assert.equal(changes, 1);
  assert.equal(currentNativeSession(key), 301);
  dropNativeSession(key);
  assert.equal(currentNativeSession(key), null);
});

test("invalid IDs cannot be persisted as capture references", () => {
  const key = sessionKey("another-case", 23);
  for (const id of [-1, 0, NaN, Infinity, 1.5]) rememberNativeSession(key, id);
  assert.equal(currentNativeSession(key), null);
});

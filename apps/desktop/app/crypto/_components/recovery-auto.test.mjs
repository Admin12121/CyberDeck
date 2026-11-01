import test from "node:test";
import assert from "node:assert/strict";
import { chooseRecoveryBackend, DEFAULT_CANDIDATES, DEFAULT_MATCHES } from "./recovery-auto.ts";

const devices = (verified) => ({
  opencl_detected: true, detail: "probe only",
  devices: [{ device_index: 2, name: "Fixture GPU", vendor: "test", driver: "test", hardware_verified: verified }],
});

test("Auto never treats an enumerated unverified GPU as safe to run", () => {
  assert.deepEqual(chooseRecoveryBackend("auto", null), { backend: "cpu" });
  assert.deepEqual(chooseRecoveryBackend("auto", devices(false)), { backend: "cpu" });
  assert.deepEqual(chooseRecoveryBackend("auto", { ...devices(true), opencl_detected: false }), { backend: "cpu" });
});
test("Auto selects an independently verified available OpenCL device, with bounded batch", () => {
  assert.deepEqual(chooseRecoveryBackend("auto", devices(true), 4096), {
    backend: "open_cl", device_index: 2, batch_size: 4096,
  });
});
test("Explicit device selection does not silently fall back to CPU", () => {
  assert.deepEqual(chooseRecoveryBackend("cpu", devices(true)), { backend: "cpu" });
  assert.deepEqual(chooseRecoveryBackend("open_cl:2", devices(false)), {
    backend: "open_cl", device_index: 2, batch_size: 4096,
  });
  assert.throws(() => chooseRecoveryBackend("cuda", null), /Invalid recovery backend/);
  assert.equal(DEFAULT_CANDIDATES, 100_000);
  assert.equal(DEFAULT_MATCHES, 1);
});

import test from "node:test";
import assert from "node:assert/strict";
import { verifyDigestOutput } from "./verify-output.ts";

test("CRC32 compares native ASCII checksum instead of hex-of-ASCII bytes", () => {
  const out = { output_b64: "Y2JmNDM5MjY=", output_hex: "6362663433393236" };
  assert.equal(verifyDigestOutput("crc32", "cbf43926", out), true);
  assert.equal(verifyDigestOutput("crc32", "00000000", out), false);
});
test("Binary digest verification uses raw digest bytes", () => {
  const out = { output_b64: "YWJj", output_hex: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" };
  assert.equal(verifyDigestOutput("sha256", "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", out), true);
  assert.equal(verifyDigestOutput("sha256", "000", out), false);
});

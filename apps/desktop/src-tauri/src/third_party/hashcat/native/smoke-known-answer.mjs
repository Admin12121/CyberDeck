#!/usr/bin/env node
/**
 * CyberDeck embedded Hashcat SHA-256 known-answer smoke, on authorized
 * deterministic fixtures only. Runs the PRIVATE bundled worker through its
 * fixed binary protocol, NOT a separately installed hashcat executable.
 *
 * Usage: node native/smoke-known-answer.mjs --runtime /absolute/hashcat/runtime
 * Fails closed if an OpenCL device/driver is missing. Never claims GPU success
 * from compilation or device enumeration alone.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

const ABSOLUTE_MAX_PATH = 4096;
const argv = process.argv.slice(2);
const flag = argv.indexOf("--runtime");
if (flag < 0 || flag + 1 >= argv.length || argv.length !== 2) {
  throw new Error("usage: --runtime /absolute/packaged/hashcat");
}
const runtime = argv[flag + 1];
if (!isAbsolute(runtime) || runtime.length > ABSOLUTE_MAX_PATH) {
  throw new Error("runtime must be an absolute, bounded path");
}
const worker = join(runtime, process.platform === "win32"
  ? "cyberdeck-recovery-worker.exe" : "cyberdeck-recovery-worker");
if (!statSync(worker).isFile()) {
  throw new Error("packaged private worker does not exist");
}

const fixture = Buffer.from("cyberdeck-embedded-mode1400-KAT", "utf8");
const target = createHash("sha256").update(fixture).digest("hex");
const scratch = mkdtempSync(join(tmpdir(), "cyberdeck-hashcat-kat-"));
const hashPath = join(scratch, "target.sha256");
const wordlistPath = join(scratch, "wordlist.txt");
const resultPath = join(scratch, "out.tmp");
const workDir = join(scratch, "work");

function pathField(path) {
  const data = Buffer.from(path, "utf8");
  if (!isAbsolute(path) || !data.length || data.length > ABSOLUTE_MAX_PATH) {
    throw new Error("invalid bounded worker path");
  }
  const len = Buffer.alloc(2);
  len.writeUInt16LE(data.length);
  return Buffer.concat([len, data]);
}
const limits = Buffer.alloc(16);
limits.writeBigUInt64LE(3n, 0); // one correct candidate among three
limits.writeUInt32LE(45, 8); // native deadline independent of supervisor
limits.writeUInt32LE(0, 12); // Hashcat-managed native default device
const request = () => Buffer.concat([
  Buffer.from("CDHC0001"), limits, ...[runtime, hashPath, wordlistPath, resultPath].map(pathField),
]);

try {
  mkdirSync(workDir, { mode: 0o700 });
  writeFileSync(hashPath, target + "\n", { mode: 0o600 });
  writeFileSync(wordlistPath, "wrong\n" + fixture.toString("utf8") + "\nalso-wrong\n", { mode: 0o600 });
  const response = spawnSync(worker, [], {
    input: request(),
    timeout: 75_000,
    maxBuffer: 4096,
    cwd: workDir,
    env: {
      ...process.env,
      HOME: workDir, XDG_CACHE_HOME: workDir, XDG_CONFIG_HOME: workDir,
      APPDATA: workDir, LOCALAPPDATA: workDir, TEMP: workDir, TMP: workDir,
    },
    stdio: ["pipe", "ignore", "ignore"],
  });
  if (response.error) throw new Error("embedded worker launch/execution failed: " + response.error.code);
  if (response.status !== 0) {
    throw new Error("embedded worker failed with numeric status " + response.status +
      "; verify compatible native OpenCL drivers, the SHA-256 module and kernels");
  }
  const output = readFileSync(resultPath);
  if (output.length > 4096) throw new Error("fixture result exceeds safe bound");
  let end = output.length;
  if (end && output[end - 1] === 10) end--;
  if (end && output[end - 1] === 13) end--;
  const recovered = output.subarray(0, end);
  const digest = createHash("sha256").update(recovered).digest();
  const expected = Buffer.from(target, "hex");
  if (!timingSafeEqual(digest, expected) || !recovered.equals(fixture)) {
    throw new Error("embedded result failed independent SHA-256 and source-wordlist verification");
  }
  process.stdout.write("PASS: embedded native Hashcat mode 1400 known-answer fixture via private worker\n");
} finally {
  rmSync(scratch, { recursive: true, force: true, maxRetries: 3 });
}

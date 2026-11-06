import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve, join, win32, posix } from "node:path";
import { fileURLToPath } from "node:url";
const vendor = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = path => readFileSync(join(vendor, path), "utf8");

// The raw digest triplet modes and the archive/document batches' explicit
// kernel sets (pure-only and optimized-only families).
const TRIPLET_MODES = [0, 100, 1000, 1400, 1700];
const ARCHIVE_KERNELS = {
  9400: ["m09400-pure.cl"],
  9600: ["m09600-pure.cl"],
  9700: ["m09700_a0-optimized.cl", "m09700_a1-optimized.cl", "m09700_a3-optimized.cl", "m09700_a4-optimized.cl"],
  10400: ["m10400_a0-optimized.cl", "m10400_a1-optimized.cl", "m10400_a3-optimized.cl", "m10400_a4-optimized.cl"],
  10500: ["m10500-pure.cl"],
  11600: ["m11600-pure.cl", "m11600-optimized.cl"],
  13600: ["m13600-pure.cl"],
  17200: ["m17200_a0-pure.cl", "m17200_a1-pure.cl", "m17200_a3-pure.cl", "m17200_a4-pure.cl"],
  17210: ["m17210_a0-pure.cl", "m17210_a1-pure.cl", "m17210_a3-pure.cl", "m17210_a4-pure.cl"],
  11300: ["m11300-pure.cl"],
  13400: ["m13400-pure.cl"],
  15600: ["m15600-pure.cl"],
  15700: ["m15700-pure.cl"],
};

test("only approved pinned module+kernel sources are bundled", () => {
  const manifest = JSON.parse(read("source-manifest.json"));
  const supported = JSON.parse(read("capability-manifest.json"));
  const build = read("build-native.mjs");
  assert.equal(manifest.commit, supported.source_commit);
  assert.equal(supported.abi_version, 4);
  assert.deepEqual(supported.hash_modes.map(m => m.id),
    [0, 10, 20, 50, 60, 100, 110, 120, 132, 400, 500, 1000, 1100, 1400, 1500, 1700, 1731, 1800, 2100, 3200, 5500, 5600, 7400, 9400, 9600, 9700, 10400, 10500, 11300, 11600, 13400, 13600, 15600, 15700, 17200, 17210]);
  for (const m of supported.hash_modes) {
    assert.ok(manifest.files["src/modules/module_" + String(m.id).padStart(5, "0") + ".c"],
      "missing module " + m.id);
    for (const attack of ["a0", "a1", "a3"]) {
      const path = "OpenCL/m" + String(m.id).padStart(5, "0") + "_" + attack + "-optimized.cl";
      if (TRIPLET_MODES.includes(m.id)) {
        assert.ok(manifest.files[path], "missing optimized mode kernel " + path);
      }
    }
    for (const kernel of ARCHIVE_KERNELS[m.id] ?? []) {
      assert.ok(manifest.files["OpenCL/" + kernel], "missing archive kernel " + kernel);
    }
    assert.equal(m.hardware_verified, false, "compilation must not imply GPU KAT");
  }
  assert.ok(build.includes("...modulePaths"));
  assert.ok(build.includes('copyFileSync(capabilityPath, join(runtime, "capability-manifest.json"))'));
  assert.ok(build.includes('copyFileSync(join(build, "modules", name), join(modeDir, name))'));
});

test("the C shim, FFI and worker use the same bounded selected-mode contract", () => {
  const c = read("native/cyberdeck_hashcat.c");
  const ffi = read("native/hashcat_ffi.rs");
  const worker = read("native/recovery_worker.rs");
  const supervisor = read("../../features/crypto/application/embedded_hashcat.rs");
  const modes = "0 | 10 | 20 | 50 | 60 | 100 | 110 | 120 | 132 | 400 | 1500 | 1731 | 500 | 1000 | 1400 | 1700 | 1800 | 3200 | 7400 | 1100 | 2100 | 5500 | 5600 | 11600 | 13600 | 17200 | 17210 | 9400 | 9600 | 9700 | 10400 | 10500 | 11300 | 13400 | 15600 | 15700";
  assert.match(c, /case 11600: case 13600: case 17200: case 17210:/);
  for (const mode of modes.split(" | ")) {
    const boundary = new RegExp("\\b" + mode + "\\b");
    assert.ok(c.includes("case " + mode + ":"), "shim allowlist misses mode " + mode);
    assert.match(ffi, boundary, "ffi allowlist misses mode " + mode);
    assert.match(worker, boundary, "worker allowlist misses mode " + mode);
  }
  assert.match(c, /--potfile-disable/);
  assert.match(c, /--restore-disable/);
  assert.match(c, /--logfile-disable/);
  assert.match(ffi, /const ABI_VERSION: u32 = 4/);
  assert.match(worker, /CDHC0001/);
  assert.match(worker, /CDHC0002/);
  assert.match(worker, /unsupported hash mode/);
  assert.match(supervisor, /fn validate_embedded_request\(/);
  assert.match(supervisor, /RecoveryTarget::parse\(&request.algorithm/);
  assert.match(supervisor, /frame_mode\(/);
});

test("native Hashcat Windows build-path and import behavior remain compatible", () => {
  const build = read("build-native.mjs");
  const ffi = read("native/hashcat_ffi.rs");
  assert.equal(win32.isAbsolute("C:\\Dev\\CyberDeck\\target\\debug\\build"), true);
  assert.equal(posix.isAbsolute("/workspace/target/debug/build"), true);
  assert.equal(win32.isAbsolute("relative\\build"), false);
  assert.match(build, /!isAbsolute\(process\.argv\[argIndex \+ 1\]\)/);
  assert.match(ffi, /kind = "raw-dylib"/);
});

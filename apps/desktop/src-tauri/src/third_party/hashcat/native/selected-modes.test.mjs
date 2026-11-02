import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve, join, win32, posix } from "node:path";
import { fileURLToPath } from "node:url";
const vendor = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = path => readFileSync(join(vendor, path), "utf8");

test("only approved pinned module+optimized kernel sources are bundled", () => {
  const manifest = JSON.parse(read("source-manifest.json"));
  const supported = JSON.parse(read("capability-manifest.json"));
  const build = read("build-native.mjs");
  assert.equal(manifest.commit, supported.source_commit);
  assert.equal(supported.abi_version, 4);
  assert.deepEqual(supported.hash_modes.map(m => m.id), [0, 100, 1000, 1400, 1700]);
  assert.deepEqual(supported.hash_modes.map(m => m.algorithm), ["md5", "sha1", "ntlm", "sha256", "sha512"]);
  for (const m of supported.hash_modes) {
    assert.ok(manifest.files["src/modules/module_" + String(m.id).padStart(5, "0") + ".c"]);
    for (const attack of ["a0", "a1", "a3"]) {
      const path = "OpenCL/m" + String(m.id).padStart(5, "0") + "_" + attack + "-optimized.cl";
      assert.ok(manifest.files[path], "missing optimized mode kernel " + path);
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
  assert.match(c, /hash_mode != 0 && hash_mode != 100 && hash_mode != 1000 && hash_mode != 1400 && hash_mode != 1700/);
  assert.match(c, /--potfile-disable/);
  assert.match(c, /--restore-disable/);
  assert.match(c, /--logfile-disable/);
  assert.match(ffi, /const ABI_VERSION: u32 = 4/);
  assert.match(ffi, /matches!\(hash_mode, 0 \| 100 \| 1000 \| 1400 \| 1700\)/);
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

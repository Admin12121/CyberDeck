import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (p) => readFileSync(p, "utf8");
const root = "apps/desktop/src-tauri";
const hc = root + "/src/third_party/hashcat";

test("Normal desktop build owns version-pinned C/shim/Rust-worker source graph", () => {
  const build = read(root + "/build.rs");
  const native = read(hc + "/build-native.mjs");
  const tauri = JSON.parse(read(root + "/tauri.conf.json"));
  const manifest = JSON.parse(read(hc + "/source-manifest.json"));
  assert.ok(build.includes('build-native.mjs'));
  assert.ok(build.includes('tauri_build::build()'));
  assert.ok(build.includes('"--install"'));
  assert.equal(manifest.commit, "1994b513b550edfe3e7fcaa1103759a9343e57a4");
  assert.equal(Object.keys(manifest.files).length, 573);
  assert.ok(manifest.files["src/modules/module_00000.c"], "upstream startup dependency must be pinned");
  assert.ok(manifest.files["src/modules/module_01400.c"], "SHA-256 selected mode must be pinned");
  assert.ok(manifest.files["OpenCL/m04000-pure.cl"], "required upstream startup kernel must be pinned");
  const caps = JSON.parse(read(hc + "/capability-manifest.json"));
  assert.deepEqual(caps.hash_modes.map(({id}) => id), [0,100,1400,1700]);
  assert.ok(caps.hash_modes.every(({hardware_verified}) => hardware_verified === false));
  assert.ok(caps.attack_modes.every(({id}) => id === 0), "only wordlist currently worker-connected");
  assert.ok(native.includes('modulePaths'), "every selected module must be compiled");
  assert.ok(native.includes('for (const name of moduleNames)'), "built modules must be installed");
  assert.ok(native.includes('native/recovery_worker.rs'));
  assert.ok(native.includes('native/cyberdeck_hashcat.c'));
  assert.ok(native.includes('rustc'));
  assert.ok(native.includes('moduleNames'), "each selected mode must have its own compiled plugin");
  assert.ok(native.includes('supportedModes'), "selected modes must be explicit in build");
  assert.equal(tauri.bundle.resources["resources/hashcat/"], "hashcat/");
  assert.ok(!native.includes('Command::new("hashcat")'));
});

test("Only private, bounded and supervised worker dispatch is exposed to Tauri", () => {
  const c = read(hc + "/native/cyberdeck_hashcat.c");
  const worker = read(hc + "/native/recovery_worker.rs");
  const supervisor = read(root + "/src/features/crypto/application/embedded_hashcat.rs");
  const controller = read(root + "/src/features/crypto/ipc/recovery.rs");
  const main = read(root + "/src/main.rs");
  for (const option of ["--potfile-disable", "--restore-disable",
    "--logfile-disable", "--outfile-format=2", "--hash-type=%u"]) {
    assert.ok(c.includes(option), option + " secret persistence/mode guard missing");
  }
  assert.ok(worker.includes('CDHC0001'));
  assert.ok(worker.includes('CDHC0002'));
  assert.ok(c.includes('cd_hashcat_prepare_mode'));
  assert.ok(c.includes('cd_hashcat_last_setup_stage'), 'C ABI must classify startup failures without raw logs');
  assert.ok(worker.includes('read_request('));
  assert.ok(supervisor.includes('Stdio::null()'));
  assert.ok(supervisor.includes('PrivateChild'));
  assert.ok(supervisor.includes('RecoveryTarget::parse(&request.algorithm'));
  assert.ok(supervisor.includes('target.is_match(candidate)'));
  assert.ok(supervisor.includes('SensitiveBytes'));
  assert.ok(supervisor.includes('tempfile::Builder'));
  assert.ok(controller.includes('start_recovery_with_wordlist_engine('));
  assert.ok(controller.includes('start_recovery_hashcat_v1') ||
    controller.includes('recovery_start_hashcat_v1'));
  assert.ok(controller.includes('recovery_backend::access'));
  assert.ok(main.includes('recovery_start_hashcat_v1'));
  assert.ok(main.includes('recovery_hashcat_capabilities_v1'));
  assert.ok(!supervisor.includes('Command::new("hashcat")'));
});

test("Hashcat opt-in preserves native Rust as default and masked-result IPC", () => {
  const ipc = read("apps/desktop/lib/ipc.ts");
  const ui = read("apps/desktop/app/crypto/_components/NativeRecoveryV1.tsx");
  assert.ok(ipc.includes('"recovery_start_hashcat_v1"'));
  assert.ok(ipc.includes('"recovery_hashcat_capabilities_v1"'));
  assert.ok(ui.includes('useState<"rust" | "hashcat">("rust")'));
  assert.ok(ui.includes('recoveryStartHashcatV1'));
  assert.match(ui, /engineChoice === "hashcat"\s*\? recoveryStartHashcatV1 : recoveryStartV1/);
  assert.ok(ui.includes('await startCommand(request,'), "selected engine must execute, not just appear in UI");
  assert.ok(ui.includes('hashcatCapability?.available'));
  assert.ok(ui.includes("GPU detection,"));
  assert.ok(ui.includes('recoveryRevealV1'));
  assert.ok(ui.includes('recoveryDiscardV1'));
  assert.ok(ui.includes('recoveryCancelV1'));
});

test("Hashcat-managed backend is explicit and never silently becomes Rust CPU/OpenCL", () => {
  const backend = read(root + "/src/features/crypto/application/recovery_backend.rs");
  const controller = read(root + "/src/features/crypto/ipc/recovery.rs");
  const supervisor = read(root + "/src/features/crypto/application/embedded_hashcat.rs");
  const ipc = read("apps/desktop/lib/ipc.ts");
  const ui = read("apps/desktop/app/crypto/_components/NativeRecoveryV1.tsx");
  assert.ok(backend.includes("HashcatManaged"));
  assert.ok(backend.includes("cannot execute through Rust recovery"));
  assert.ok(controller.includes("recovery engine and backend selection do not match"));
  assert.ok(supervisor.includes("BackendSelection::HashcatManaged"));
  assert.ok(ipc.includes('"hashcat_managed"'));
  assert.ok(ui.includes('{ backend: "hashcat_managed" }'));
  assert.ok(ui.includes('engineChoice === "hashcat"'));
  assert.ok(read(hc + "/native/smoke-known-answer.mjs").includes("spawnSync(worker"));
});

test("Hashcat capabilities probe exactly the private worker with a bounded, secret-free loader check", () => {
  const header = read(hc + "/native/cyberdeck_hashcat.h");
  const shim = read(hc + "/native/cyberdeck_hashcat.c");
  const worker = read(hc + "/native/recovery_worker.rs");
  const ffi = read(hc + "/native/hashcat_ffi.rs");
  const controller = read(root + "/src/features/crypto/ipc/recovery.rs");
  const supervisor = read(root + "/src/features/crypto/application/embedded_hashcat.rs");
  assert.ok(header.includes("cd_hashcat_opencl_loader_available"));
  assert.ok(shim.includes('hc_dlopen ("libOpenCL.so")'));
  assert.ok(ffi.includes("const ABI_VERSION: u32 = 4"));
  assert.ok(worker.includes('--probe-opencl-loader'));
  assert.ok(worker.includes("std::process::exit(10)"));
  assert.ok(supervisor.includes("pub fn probe_opencl_loader("));
  assert.ok(supervisor.includes("Duration::from_secs(3)"));
  assert.ok(supervisor.includes("Stdio::null()"));
  assert.ok(controller.includes("embedded_hashcat::probe_opencl_loader(&runtime)"));
  assert.ok(controller.includes("available: false"));
  assert.ok(controller.includes("hardware_verified: false"));
});

test("four bundled wordlist modes are explicitly validated and desktop-selectable", () => {
  const core = read(root + "/src/features/crypto/application/embedded_hashcat.rs");
  const controller = read(root + "/src/features/crypto/ipc/recovery.rs");
  const backend = read(root + "/src/features/crypto/application/recovery_backend.rs");
  const ui = read("apps/desktop/app/crypto/_components/NativeRecoveryV1.tsx");
  const ipc = read("apps/desktop/lib/ipc.ts");
  for (const [algorithm, mode] of [["md5",0],["sha1",100],["sha256",1400],["sha512",1700]]) {
    assert.ok(core.includes('"' + algorithm + '" => ' + mode + ','), algorithm + " not validated");
    assert.ok(ui.includes('value: "' + algorithm + '"'), algorithm + " not selectable");
    assert.ok(backend.includes('"'+ algorithm + '" => "embedded_hashcat_'), algorithm + " summary mislabeled");
    assert.ok(ipc.includes('"'+ algorithm + '"'), algorithm + " absent from typed request");
  }
  assert.ok(controller.includes("embedded_hashcat::validate_embedded_request(&request)?"));
  assert.ok(ui.includes('algorithm: engineChoice === "hashcat" ? hashcatAlgorithm : "sha256"'));
  assert.ok(ui.includes("digest length alone is not proof") ||
    ui.includes("digest length alone is not proof of its algorithm"));
  assert.ok(core.includes("target.is_match(candidate)"));
  assert.ok(core.includes("Hashcat output is not a verified original wordlist candidate"));
});

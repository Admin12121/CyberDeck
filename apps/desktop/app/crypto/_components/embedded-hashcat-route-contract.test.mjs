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
  assert.equal(Object.keys(manifest.files).length, 562);
  assert.ok(manifest.files["src/modules/module_00000.c"], "upstream startup dependency must be pinned");
  assert.ok(manifest.files["src/modules/module_01400.c"], "SHA-256 selected mode must be pinned");
  assert.ok(manifest.files["OpenCL/m04000-pure.cl"], "required upstream startup kernel must be pinned");
  assert.deepEqual(manifest.supportedModesPlanned, [1400], "bootstrap MD5 mode is not a supported public recovery mode");
  assert.ok(native.includes('modules/' + '" + module')); // upstream real mode plugin
  assert.ok(native.includes('native/recovery_worker.rs'));
  assert.ok(native.includes('native/cyberdeck_hashcat.c'));
  assert.ok(native.includes('rustc'));
  assert.ok(native.includes('bootstrapModule'), 'native bootstrap module must be compiled and packaged');
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
    "--logfile-disable", "--outfile-format=2", "--hash-type=1400"]) {
    assert.ok(c.includes(option), option + " secret persistence/mode guard missing");
  }
  assert.ok(worker.includes('CDHC0001'));
  assert.ok(c.includes('cd_hashcat_last_setup_stage'), 'C ABI must classify startup failures without raw logs');
  assert.ok(worker.includes('read_request('));
  assert.ok(supervisor.includes('Stdio::null()'));
  assert.ok(supervisor.includes('PrivateChild'));
  assert.ok(supervisor.includes('RecoveryTarget::parse("sha256"'));
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

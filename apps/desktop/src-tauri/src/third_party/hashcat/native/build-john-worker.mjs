#!/usr/bin/env node
// Compile CyberDeck's supervised john DLL worker helper from its pinned
// source. This mirrors build-native.mjs's recovery-worker compile step but
// is a separate script because the john DLL bundle is owned by the john
// track and build-native.mjs must stay untouched.
//
// Output (default): apps/desktop/src-tauri/resources/engines/
//   <platform>/cyberdeck-john-worker[.exe]  — bundle beside john.dll, john.exe
//   and the MinGW runtime deps (libcrypto-3-x64.dll, libgomp-1.dll,
//   libwinpthread-1.dll) in resources/engines/ so the app's DLL-branch
//   resolver finds the full set in one directory.
//
// The helper links john.dll through Rust raw-dylib: the import library is
// generated from the fixed C ABI at compile time, so john.dll itself is NOT
// needed to compile — only at runtime, beside the helper.
//
// Usage: bun build-john-worker.mjs [output-dir]   (default resources/engines)
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdirSync } from "node:fs";

const root = resolve(dirname(fileURLToPath(import.meta.url)));
const srcTauri = resolve(root, "../../../..");
const outputDir = process.argv[2]
  ? resolve(process.argv[2])
  : join(srcTauri, "resources", "engines");

const workerName = process.platform === "win32"
  ? "cyberdeck-john-worker.exe" : "cyberdeck-john-worker";
const workerSource = join(root, "john_worker.rs");

// Same flags as build-native.mjs's worker compile: optimized, aborting
// panics (the helper's failure mode is a numeric exit code, never an
// unwind). No -L search path is needed — raw-dylib carries its own stubs.
const flags = [
  "--edition=2021",
  "-C", "opt-level=2",
  "-C", "panic=abort",
  "-o", join(outputDir, workerName),
  workerSource,
];

mkdirSync(outputDir, { recursive: true });
const checked = spawnSync(process.env.RUSTC || "rustc", flags, { stdio: "inherit" });
if (checked.status !== 0) {
  throw new Error(`john worker helper compile failed (${checked.status})`);
}
console.log(`compiled ${join(outputDir, workerName)}`);
console.log(
  "bundle beside it in the same engines directory: john.dll, john.exe, john.conf",
  "and the MinGW runtime deps the DLL imports (libcrypto-3-x64.dll,",
  "libgomp-1.dll, libwinpthread-1.dll) — the resolver requires the full set",
);

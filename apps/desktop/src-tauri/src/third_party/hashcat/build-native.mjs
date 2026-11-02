#!/usr/bin/env node
/**
 * CyberDeck pinned embedded Hashcat source build.
 * SPDX-License-Identifier: MIT
 *
 * Builds upstream shared CORE + selected raw-digest modules, CyberDeck narrow
 * native C shim, and a private runtime tree. Does NOT build or execute hashcat
 * CLI, fetch anything, access the ignored reference/ directory, or alter Cargo.
 *
 * npm/node are already available for CyberDeck's Next.js/Tauri frontend.
 * Usage:
 *   node apps/desktop/src-tauri/src/third_party/hashcat/build-native.mjs --out /absolute/output
 *
 * The integration owner must call this from the normal desktop Cargo build
 * and bundle runtime/ beside the private recovery worker. The source/manifest
 * are shipped with the tracked repository, not downloaded at runtime.
 */
import { readFileSync, copyFileSync, mkdirSync, cpSync, existsSync, statSync } from "node:fs";
import { dirname, resolve, join, sep, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

const root = dirname(fileURLToPath(import.meta.url));
const source = join(root, "upstream");
const manifestPath = join(root, "source-manifest.json");
const capabilityPath = join(root, "capability-manifest.json");
const capabilities = JSON.parse(readFileSync(capabilityPath, "utf8"));
if (capabilities.schema !== 1 ||
    capabilities.source_commit !== "1994b513b550edfe3e7fcaa1103759a9343e57a4" ||
    capabilities.abi_version !== 4 ||
    capabilities.hash_modes.map(x => x.id).join(",") !== "0,100,400,500,1000,1400,1700,1800,3200") {
  throw new Error("embedded Hashcat capability manifest conflicts with pinned C/worker contract");
}
const argIndex = process.argv.indexOf("--out");
if (argIndex < 0 || !process.argv[argIndex + 1] || !isAbsolute(process.argv[argIndex + 1])) {
  console.error("usage: node build-native.mjs --out /absolute/build-output");
  process.exit(2);
}
const output = resolve(process.argv[argIndex + 1]);
const installIndex = process.argv.indexOf("--install");
const install = installIndex >= 0 && process.argv[installIndex + 1]
  ? resolve(process.argv[installIndex + 1]) : null;
if (output === root || root.startsWith(output + sep) || output.startsWith(root + sep)) {
  throw new Error("build output must not overlap vendored sources");
}
if (install && (install === root || root.startsWith(install + sep) || install.startsWith(root + sep)
  || install === output || install.startsWith(output + sep) || output.startsWith(install + sep))) {
  throw new Error("package install must not overlap source or build inputs");
}
const files = JSON.parse(readFileSync(manifestPath, "utf8"));
if (files.schema !== 1 || files.commit !== "1994b513b550edfe3e7fcaa1103759a9343e57a4") {
  throw new Error("Hashcat provenance revision mismatch");
}
const hash = (data) => createHash("sha256").update(data).digest("hex");
for (const [rel, expected] of Object.entries(files.files)) {
  if (rel.startsWith("/") || rel.split("/").includes("..")) throw new Error("unsafe vendor path");
  const target = resolve(source, rel);
  if (!target.startsWith(source + sep)) throw new Error("vendored path escape");
  const data = readFileSync(target);
  if (data.length !== expected.bytes || hash(data) !== expected.sha256) {
    throw new Error("Hashcat vendored file does not match pinned source: " + rel);
  }
}

if (!["linux", "darwin", "win32"].includes(process.platform)) {
  throw new Error("embedded Hashcat build host unsupported: " + process.platform);
}
if (process.env.CARGO_CFG_TARGET_OS) {
  const host = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "macos" : "linux";
  if (process.env.CARGO_CFG_TARGET_OS !== host) {
    throw new Error("cross-compile of embedded Hashcat not verified; use matched native target");
  }
}
const build = join(output, "build");
const runtime = join(output, "runtime");
mkdirSync(build, { recursive: true });
mkdirSync(runtime, { recursive: true });
for (const rel of Object.keys(files.files)) {
  const target = join(build, rel);
  mkdirSync(dirname(target), { recursive: true });
  const from = join(source, rel);
  if (existsSync(target)) {
    // Refuse to mask local source deviations or concurrent build writers.
    if (hash(readFileSync(target)) === hash(readFileSync(from))) continue;
    throw new Error("build tree changed from tracked upstream: " + rel);
  }
  copyFileSync(from, target);
}
for (const folder of ["obj", "modules", "feeds", "bridges"]) {
  mkdirSync(join(build, folder), { recursive: true });
}
const library = process.platform === "win32" ? "hashcat.dll" :
  process.platform === "darwin" ? "libhashcat.8.dylib" : "libhashcat.so.8";
// These are bundled native hash modes, not claims of validated GPU execution.
const supportedModes = [
  { id: 0, algorithm: "md5" },
  { id: 100, algorithm: "sha1" },
  { id: 400, algorithm: "phpass" },
  { id: 500, algorithm: "md5crypt" },
  { id: 1000, algorithm: "ntlm" },
  { id: 1400, algorithm: "sha256" },
  { id: 1700, algorithm: "sha512" },
  { id: 1800, algorithm: "sha512crypt" },
  { id: 3200, algorithm: "bcrypt" },
];
const moduleNames = supportedModes.map(({ id }) =>
  "module_" + String(id).padStart(5, "0") +
  (process.platform === "win32" ? ".dll" : ".so"));
const modulePaths = moduleNames.map((name) => "modules/" + name);
const shim = process.platform === "win32" ? "cyberdeck_hashcat_shim.dll" :
  process.platform === "darwin" ? "libcyberdeck_hashcat_shim.dylib" : "libcyberdeck_hashcat_shim.so";
function checked(executable, args, cwd) {
  const z = spawnSync(executable, args, {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
    timeout: 600_000,
    env: { ...process.env, SOURCE_DATE_EPOCH: process.env.SOURCE_DATE_EPOCH || "1793534400" },
  });
  if (z.error?.code === "ENOENT") {
    const prerequisites = process.platform === "win32"
      ? "Windows source builds require MSYS2 UCRT64 GNU Make, GCC and their Unix utilities on PATH (along with Node.js and Rust)."
      : "Install the native GNU Make, C compiler and Rust build toolchain.";
    throw new Error(`required native Hashcat build executable not found: ${executable}. ${prerequisites}`);
  }
  if (z.error || z.status !== 0) {
    const tail = ((z.stderr || "") + "\n" + (z.stdout || "")).slice(-4500);
    throw new Error(executable + " failed: " + (z.error || "exit " + z.status) + "\n" + tail);
  }
  console.log(executable + " accepted: " + args.slice(-2).join(" "));
}
// The upstream Windows makefile uses GCC/MinGW, not the MSVC cl.exe ABI.
// MSYS2 UCRT64 ships gcc.exe; cc.exe is not consistently available on PATH.
const c = process.env.CC || (process.platform === "win32" ? "gcc" : "cc");
checked(process.env.MAKE || "make",
  ["-j2", "PRODUCTION=1", "SHARED=1", "ENABLE_BRAIN=0", "ENABLE_CUBIN=0",
   "MAINTAINER_MODE=1", library, ...modulePaths], build);

const includes = ["-I" + join(root, "native"), "-I" + join(build, "include"),
  "-I" + join(build, "OpenCL"), "-I" + join(build, "deps/OpenCL-Headers")];
const shimSource = join(root, "native/cyberdeck_hashcat.c");
const libPath = join(build, library);
if (process.platform === "win32") {
  // Explicitly not claiming MSVC support: the pinned upstream DLL uses
  // __declspec exports but MSYS2/MinGW runtime validation remains required.
  checked(c, ["-std=gnu99", "-O2", "-shared", "-DCYBERDECK_HASHCAT_BUILD",
    ...includes, "-o", join(runtime, shim), shimSource, libPath], build);
} else {
  const args = ["-std=gnu99", "-O2", "-fPIC", "-shared", "-Wall", "-Wextra",
    "-Werror", ...includes, "-o", join(runtime, shim), shimSource, libPath];
  if (process.platform === "linux") args.push("-Wl,-rpath,$ORIGIN", "-Wl,-z,defs");
  else args.push("-Wl,-rpath,@loader_path");
  checked(c, args, build);
}
copyFileSync(libPath, join(runtime, library));
// Build a separately supervised, narrow Rust worker from the same pinned
// runtime. It receives a versioned, bounded binary frame via stdin; there is
// no generic CLI argument forwarding or external installed hashcat executable.
const workerName = process.platform === "win32"
  ? "cyberdeck-recovery-worker.exe" : "cyberdeck-recovery-worker";
const workerSource = join(root, "native/recovery_worker.rs");
const workerFlags = [
  "--edition=2021", "-C", "opt-level=2", "-C", "panic=abort",
  "-L", "native=" + runtime,
  "-o", join(runtime, workerName), workerSource,
];
if (process.platform === "linux") {
  workerFlags.push("-C", "link-arg=-Wl,-rpath,$ORIGIN");
} else if (process.platform === "darwin") {
  workerFlags.push("-C", "link-arg=-Wl,-rpath,@loader_path");
}
checked(process.env.RUSTC || "rustc", workerFlags, build);

const modeDir = join(runtime, "modules");
mkdirSync(modeDir, { recursive: true });
for (const name of moduleNames) {
  copyFileSync(join(build, "modules", name), join(modeDir, name));
}
cpSync(join(build, "OpenCL"), join(runtime, "OpenCL"), { recursive: true });
cpSync(join(build, "tunings"), join(runtime, "tunings"), { recursive: true });
const licenses = join(runtime, "licenses");
mkdirSync(licenses, { recursive: true });
copyFileSync(join(build, "docs/license.txt"), join(licenses, "HASHCAT_MIT.txt"));
copyFileSync(join(build, "docs/credits.txt"), join(licenses, "HASHCAT_CREDITS.txt"));
copyFileSync(join(build, "deps/OpenCL-Headers/LICENSE"), join(licenses, "OPENCL_HEADERS.txt"));
copyFileSync(join(build, "deps/sse2neon/LICENSE"), join(licenses, "SSE2NEON.txt"));
cpSync(join(build, "docs/license_libs"), join(licenses, "upstream_notices"), { recursive: true });
copyFileSync(manifestPath, join(runtime, "source-manifest.json"));
copyFileSync(capabilityPath, join(runtime, "capability-manifest.json"));
for (const name of [library, shim, workerName, ...modulePaths, "source-manifest.json", "capability-manifest.json"]) {
  if (!statSync(join(runtime, name)).isFile()) throw new Error("package missing " + name);
}
if (install) {
  mkdirSync(install, { recursive: true });
  cpSync(runtime, install, { recursive: true, force: true });
  for (const name of [library, shim, workerName, ...modulePaths, "source-manifest.json", "capability-manifest.json"]) {
    if (!statSync(join(install, name)).isFile()) throw new Error("installed package missing " + name);
  }
  console.log("CyberDeck managed Hashcat runtime staged for Tauri resources:", install);
}
console.log("Embedded Hashcat source-compiled runtime ready:", runtime);
console.log("Bundled selected modules:", supportedModes.map(x => x.id + ":" + x.algorithm).join(", "));
console.log("Actual GPU/device execution remains unverified until a host known-answer test.");

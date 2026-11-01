#!/usr/bin/env node
/**
 * CyberDeck pinned embedded Hashcat source build.
 * SPDX-License-Identifier: MIT
 *
 * Builds upstream shared CORE + selected SHA-256 module, CyberDeck narrow
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
import { dirname, resolve, join, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

const root = dirname(fileURLToPath(import.meta.url));
const source = join(root, "upstream");
const manifestPath = join(root, "source-manifest.json");
const argIndex = process.argv.indexOf("--out");
if (argIndex < 0 || !process.argv[argIndex + 1] || !resolve(process.argv[argIndex + 1]).startsWith(sep)) {
  console.error("usage: node build-native.mjs --out /absolute/build-output");
  process.exit(2);
}
const output = resolve(process.argv[argIndex + 1]);
if (output === root || root.startsWith(output + sep) || output.startsWith(root + sep)) {
  throw new Error("build output must not overlap vendored sources");
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
const module = process.platform === "win32" ? "module_01400.dll" : "module_01400.so";
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
  if (z.error || z.status !== 0) {
    const tail = ((z.stderr || "") + "\n" + (z.stdout || "")).slice(-4500);
    throw new Error(executable + " failed: " + (z.error || "exit " + z.status) + "\n" + tail);
  }
  console.log(executable + " accepted: " + args.slice(-2).join(" "));
}
const c = process.env.CC || "cc";
checked(process.env.MAKE || "make",
  ["-j2", "PRODUCTION=1", "SHARED=1", "ENABLE_BRAIN=0", "ENABLE_CUBIN=0",
   "MAINTAINER_MODE=1", library, "modules/" + module], build);

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
const modeDir = join(runtime, "modules");
mkdirSync(modeDir, { recursive: true });
copyFileSync(join(build, "modules", module), join(modeDir, module));
cpSync(join(build, "OpenCL"), join(runtime, "OpenCL"), { recursive: true });
cpSync(join(build, "tunings"), join(runtime, "tunings"), { recursive: true });
const licenses = join(runtime, "licenses");
mkdirSync(licenses, { recursive: true });
copyFileSync(join(build, "docs/license.txt"), join(licenses, "HASHCAT_MIT.txt"));
copyFileSync(join(build, "docs/credits.txt"), join(licenses, "HASHCAT_CREDITS.txt"));
copyFileSync(join(build, "deps/OpenCL-Headers/LICENSE"), join(licenses, "OPENCL_HEADERS.txt"));
copyFileSync(join(build, "deps/sse2neon/LICENSE"), join(licenses, "SSE2NEON.txt"));
copyFileSync(manifestPath, join(runtime, "source-manifest.json"));
for (const name of [library, shim, "modules/" + module, "source-manifest.json"]) {
  if (!statSync(join(runtime, name)).isFile()) throw new Error("package missing " + name);
}
console.log("Embedded Hashcat source-compiled runtime ready:", runtime);
console.log("Mode: 1400 SHA-256 only. No device/algorithm execution is implied.");

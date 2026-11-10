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
import { readFileSync, copyFileSync, mkdirSync, cpSync, existsSync, statSync, readdirSync } from "node:fs";
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
    capabilities.hash_modes.map(x => x.id).join(",") !== "0,10,20,50,100,110,120,121,122,131,132,150,300,400,500,1000,1100,1400,1500,1700,1731,1800,2100,3100,3200,5500,5600,7400,9400,9600,9700,10400,10500,10600,11300,11600,12500,13000,13100,13400,13600,15600,15700,16800,17200,17210,18200,19600,19700,22000,22100,24100,29541,34300,34301") {
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
  { id: 500, algorithm: "md5crypt" },
  { id: 1000, algorithm: "ntlm" },
  { id: 1400, algorithm: "sha256" },
  { id: 1700, algorithm: "sha512" },
  { id: 400, algorithm: "phpass" },
  { id: 1800, algorithm: "sha512crypt" },
  { id: 3200, algorithm: "bcrypt" },
  { id: 10, algorithm: "md5-pass-salt" },
  { id: 20, algorithm: "md5-salt-pass" },
  { id: 50, algorithm: "hmac-md5" },
  { id: 150, algorithm: "hmac-sha1" },
  { id: 110, algorithm: "sha1-pass-salt" },
  { id: 120, algorithm: "sha1-salt-pass" },
  { id: 1100, algorithm: "mscash" },
  { id: 2100, algorithm: "mscash2" },
  { id: 5500, algorithm: "netntlm-v1" },
  { id: 5600, algorithm: "netntlm-v2" },
  { id: 7400, algorithm: "sha256crypt" },
  { id: 1500, algorithm: "descrypt" },
  { id: 1731, algorithm: "mssql-2012" },
  { id: 132, algorithm: "mssql-2005" },
  // Batch-6 Kerberos etype 23 + BitLocker.
  { id: 13100, algorithm: "kerberos-tgs-rep" },
  { id: 18200, algorithm: "kerberos-as-rep" },
  { id: 22100, algorithm: "bitlocker" },
  // Batch-5 wallets (KeePass, Bitcoin, Ethereum PBKDF2/scrypt).
  { id: 11300, algorithm: "bitcoin" },
  { id: 13400, algorithm: "keepass" },
  { id: 15600, algorithm: "ethereum-pbkdf2" },
  { id: 15700, algorithm: "ethereum-scrypt" },
  // Batch-4 documents (MS Office and PDF).
  { id: 9700, algorithm: "office-97-2003" },
  { id: 9400, algorithm: "office-2007" },
  { id: 9600, algorithm: "office-2013" },
  { id: 10400, algorithm: "pdf-1.1-1.3" },
  { id: 10500, algorithm: "pdf-1.4-1.6" },
  // Batch-3 archive containers (one algorithm, mode chosen by entry shape).
  { id: 11600, algorithm: "7zip" },
  { id: 13600, algorithm: "winzip-aes" },
  { id: 17200, algorithm: "zip-legacy" },
  { id: 17210, algorithm: "zip-legacy" },
  // Batch-7 databases (MSSQL 2000, MySQL 4.1, Oracle H:).
  { id: 121, algorithm: "smf" },
  { id: 122, algorithm: "macos-salted-sha1" },
  { id: 131, algorithm: "mssql-2000" },
  { id: 300, algorithm: "mysql4.1" },
  { id: 3100, algorithm: "oracle-h" },
  // Batch-8 os-and-apps: RAR3-hp/RAR5 archives, Kerberos etype 17/18 and
  // KeePass KDBX v4 (one algorithm, mode chosen by the parsed KDF UUID).
  { id: 12500, algorithm: "rar3-hp" },
  { id: 13000, algorithm: "rar5" },
  { id: 19600, algorithm: "kerberos-tgs-rep-17" },
  { id: 19700, algorithm: "kerberos-tgs-rep-18" },
  { id: 34300, algorithm: "keepass-kdbx4" },
  { id: 34301, algorithm: "keepass-kdbx4" },
  // Batch-9 salted variants: SMF, PDF 1.7 Level 3, WPA-PMKID, unified WPA
  // and the LUKS v1 RIPEMD-160 + AES text form (binary 14600 stays deferred).
  { id: 10600, algorithm: "pdf-1.7" },
  { id: 16800, algorithm: "wpa-pmkid" },
  { id: 22000, algorithm: "wpa" },
  { id: 24100, algorithm: "mongodb-scram" },
  { id: 29541, algorithm: "luks" },
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
   "MAINTAINER_MODE=1", library, "feeds", ...modulePaths], build);

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
cpSync(join(build, "feeds"), join(runtime, "feeds"), { recursive: true });
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
const feedLibs = existsSync(join(build, "feeds"))
  ? readdirSync(join(build, "feeds")).filter((name) => name.endsWith(".dll") || name.endsWith(".so"))
  : [];
for (const name of feedLibs) {
  copyFileSync(join(build, "feeds", name), join(runtime, "feeds", name));
}
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

#!/usr/bin/env node
// CyberDeck Hashcat native-source vendor/verify tool.
// The research reference is NEVER read by a normal production build.
// Usage: node apps/desktop/src-tauri/src/third_party/hashcat/vendor.mjs --import
//        node apps/desktop/src-tauri/src/third_party/hashcat/vendor.mjs --verify
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { resolve, dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../../../../../..");
const reference = resolve(repo, "reference/hashcat");
const vendor = resolve(here, "upstream");
const fileManifest = resolve(here, "source-manifest.json");
const pin = "1994b513b550edfe3e7fcaa1103759a9343e57a4";
const mode = process.argv[2];
if (mode !== "--import" && mode !== "--verify") {
  console.error("usage: node apps/desktop/src-tauri/src/third_party/hashcat/vendor.mjs --import|--verify");
  process.exit(2);
}
const hash = (data) => createHash("sha256").update(data).digest("hex");
const slash = (p) => p.split(sep).join("/");
const file = (rel) => resolve(reference, rel);
const entries = new Set();
const add = (path) => {
  if (path.startsWith("/") || path.split("/").includes("..") || !existsSync(file(path)) || !statSync(file(path)).isFile()) {
    throw new Error("missing or unsafe dependency: " + path);
  }
  entries.add(slash(path));
};
const dirFiles = (directory, predicate) => {
  for (const name of readdirSync(file(directory))) {
    const path = directory + "/" + name;
    if (statSync(file(path)).isFile() && predicate(name)) add(path);
  }
};
if (mode === "--import") {
  add("Makefile");
  add("src/Makefile");
  add("src/rust_toolchain.mk");
  // Native Windows DLL resource and UTF-8 manifest, but not the standalone CLI.
  for (const rel of ["src/hashcat_dll.rc", "src/hashcat.rc", "src/hashcat.manifest"]) add(rel);
  const makefile = readFileSync(file("src/Makefile"), "utf8");
  const variables = new Map();
  for (const line of makefile.split(/\r?\n/)) {
    const m = /^(\w+)\s*(:=|\+=)\s*(.*)$/.exec(line);
    if (!m || !["OBJS_ALL", "EMU_OBJS_ALL"].includes(m[1])) continue;
    const rest = (m[2] === ":=" ? "" : (variables.get(m[1]) ?? "") + " ") + m[3];
    variables.set(m[1], rest);
  }
  const emu = (variables.get("EMU_OBJS_ALL") ?? "").trim().split(/\s+/);
  const core = (variables.get("OBJS_ALL") ?? "")
    .replace(/\$\(EMU_OBJS_ALL\)/g, emu.join(" "))
    .trim().split(/\s+/)
    .filter((name) => name && name !== "brain");
  if (core.length < 100 || !core.includes("hashcat") || !core.includes("backend") || !core.includes("emu_inc_hash_sha256")) {
    throw new Error("could not safely resolve upstream core object closure");
  }
  for (const name of core) add("src/" + name + ".c");
  dirFiles("include", (name) => name.endsWith(".h") || name.endsWith(".def"));
  // The complete host EMU object family uses almost all common inc_ sources,
  // not only the kernel for hash mode 1400.
  dirFiles("OpenCL", (name) => /^inc_.*\.(?:h|cl)$/.test(name));
  // Raw digest modules: one kernel triplet per bundled mode.
  for (const mode of ["00000", "00100", "01000", "01400", "01700"]) {
    for (const id of ["a0", "a1", "a3"]) {
      add("OpenCL/m" + mode + "_" + id + "-optimized.cl");
    }
  }
  for (const id of ["a0", "a1", "a3"]) {
    add("OpenCL/amp_" + id + ".cl");
  }
  // Upstream source initialization requires this generic recipe kernel even
  // when the selected attack uses SHA-256 mode 1400.
  add("OpenCL/m04000-pure.cl");
  // Upstream initializes its default module 00000 before switching to 1400.
  // It is a native bootstrap dependency, not an exposed CyberDeck mode.
  add("src/modules/module_00000.c");
  add("src/modules/module_00100.c");
  add("src/modules/module_01000.c");
  add("src/modules/module_01400.c");
  add("src/modules/module_01700.c");
  // Batch-1 KDF/raw modes: phpass, md5crypt, sha512crypt, bcrypt. Modules and
  // kernels are upstream MIT files used verbatim; inc_* dependencies are
  // already included wholesale above.
  for (const mode of ["00400", "00500", "01800", "03200"]) {
    add("src/modules/module_" + mode + ".c");
  }
  // Batch-2 modes: salted digests (10/20/110/120), HMAC (50/60), Windows auth
  // (1100/2100/5500/5600) and sha256crypt (7400).
  for (const mode of ["00010", "00020", "00050", "00060", "00110", "00120",
                      "01100", "02100", "05500", "05600", "07400", "01500", "00132", "01731"]) {
    add("src/modules/module_" + mode + ".c");
  }
  dirFiles("OpenCL", (name) =>
    /^m(00010|00020|00050|00060|00110|00120|01100|02100|05500|05600|07400|01500|00132|01731)[-_a-z0-9]*\.cl$/.test(name));
  for (const kernel of [
    "OpenCL/m00400-optimized.cl",
    "OpenCL/m00500-optimized.cl",
    "OpenCL/m00500-pure.cl",
    "OpenCL/m01800-optimized.cl",
    "OpenCL/m01800-pure.cl",
    "OpenCL/m03200-pure.cl",
  ]) {
    add(kernel);
  }
  // Modern hashcat's OpenCL function prototypes are loaded dynamically.
  dirFiles("deps/OpenCL-Headers/CL", (name) => name.endsWith(".h"));
  add("deps/OpenCL-Headers/LICENSE");
  add("deps/sse2neon/sse2neon.h");
  add("deps/sse2neon/LICENSE");
  // The runtime autotune paths may load these device/system tables.
  dirFiles("tunings", (name) => name.endsWith(".hctune"));
  add("docs/license.txt");
  add("docs/credits.txt");
  add("docs/license_libs/OPENCL_HEADERS_LICENSE.txt");
  add("docs/license_libs/SSE2NEON_LICENSE.txt");

  // No overwriting a local modification silently when re-importing.
  const paths = Array.from(entries).sort();
  for (const rel of paths) {
    const data = readFileSync(file(rel));
    const target = resolve(vendor, rel);
    if (existsSync(target) && hash(readFileSync(target)) !== hash(data)) {
      throw new Error("local vendor differs; refusing destructive overwrite: " + rel);
    }
  }
  for (const rel of paths) {
    const target = resolve(vendor, rel);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(file(rel), target);
  }
  for (const rel of ["obj/.gitkeep", "modules/.gitkeep", "bridges/.gitkeep", "feeds/.gitkeep"]) {
    const target = resolve(vendor, rel);
    mkdirSync(dirname(target), { recursive: true });
    if (!existsSync(target)) writeFileSync(target, "");
  }
  const files = Object.fromEntries(paths.map((rel) => {
    const data = readFileSync(file(rel));
    return [rel, { sha256: hash(data), bytes: data.length }];
  }));
  writeFileSync(fileManifest, JSON.stringify({
    schema: 1,
    upstream: "https://github.com/hashcat/hashcat",
    commit: pin,
    version: "v8.0.0-development",
    build: "SHARED=1 PRODUCTION=1 ENABLE_BRAIN=0 ENABLE_CUBIN=0; module_00000 bootstrap + module_01400",
    supportedModesPlanned: [1400],
    includes: ["C core Makefile object closure", "all public and internal C headers", "host EMU kernel includes", "SHA-256 kernels and amplifiers", "batch-1 KDF kernels (phpass/md5crypt/sha512crypt/bcrypt)", "OpenCL headers", "sse2neon compatibility", "runtime tunings", "licenses"],
    excludes: ["standalone hashcat CLI", "hash modules beyond the bundled batch-1 set (0,100,400,500,1000,1400,1700,1800,3200)", "other mode kernels", "Python", "FPGA", "unused bridges and feeds", "docs/examples/test suites"],
    files,
  }, null, 2) + "\n");
  console.log("Imported " + paths.length + " pinned source and license files (" + core.length + " C core objects).");
}
const manifest = JSON.parse(readFileSync(fileManifest, "utf8"));
if (manifest.commit !== pin || manifest.schema !== 1) throw new Error("upstream provenance mismatch");
let total = 0;
for (const [rel, info] of Object.entries(manifest.files)) {
  const path = resolve(vendor, rel);
  if (!path.startsWith(vendor + sep)) throw new Error("unsafe manifest path");
  const data = readFileSync(path);
  if (data.length !== info.bytes || hash(data) !== info.sha256) throw new Error("vendored source altered: " + rel);
  total += data.length;
}
console.log("Verified " + Object.keys(manifest.files).length + " vendored files, " + total + " bytes, commit " + pin);

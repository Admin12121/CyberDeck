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
  const bundledModePrefixes = ["00000", "00010", "00020", "00050", "00060", "00100", "00110", "00120", "00132", "00400", "00500", "01100", "01400", "01500", "01700", "01731", "01800", "02100", "03200", "05500", "05600", "07400", "11600", "13600", "17200", "17210", "09400", "09600", "09700", "10400", "10500", "11300", "13400", "15600", "15700", "13100", "18200", "22100"];
  dirFiles("OpenCL", (name) => {
    if (name.endsWith(".h")) return true;
    if (!name.endsWith(".cl")) return false;
    if (/^(inc_|shared|markov_)/.test(name)) return true;
    return bundledModePrefixes.some((p) => name.startsWith("m" + p));
  });
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
  dirFiles("OpenCL", (name) => name.startsWith("m04000"));
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
  // Batch-3 archive containers: WinZip AES (13600), 7-Zip (11600) and PKZIP
  // legacy ZipCrypto (17200/17210).
  for (const mode of ["11600", "13600", "17200", "17210"]) {
    add("src/modules/module_" + mode + ".c");
  }
  // Batch-4 documents: MS Office 97/2003 MD5+RC4 (9700), Office 2007 (9400),
  // Office 2013 (9600), PDF 1.1-1.3 (10400) and PDF 1.4-1.6 (10500).
  for (const mode of ["09400", "09600", "09700", "10400", "10500"]) {
    add("src/modules/module_" + mode + ".c");
  }
  // Batch-5 wallets: KeePass KDBX v2/v3 (13400), Bitcoin wallet.dat (11300),
  // Ethereum PBKDF2 (15600) and Ethereum scrypt (15700).
  for (const mode of ["11300", "13400", "15600", "15700"]) {
    add("src/modules/module_" + mode + ".c");
  }
  // Batch-6: Kerberos etype 23 TGS-REP/AS-REP (13100/18200) and BitLocker (22100).
  for (const mode of ["13100", "18200", "22100"]) {
    add("src/modules/module_" + mode + ".c");
  }
  // Shared module-common sources included verbatim by batch modules.
  add("src/modules/blowfish_common.c");
  add("src/modules/scrypt_common.c");
  // Candidate-feed plugins: the wordlist reader (and siblings) are loadable
  // plugins in this hashcat; a wordlist attack cannot start without them.
  dirFiles("src/feeds", (name) => name.endsWith(".c") || name.endsWith(".h"));
  dirFiles("OpenCL", (name) =>
    /^m(00010|00020|00050|00060|00110|00120|01100|02100|05500|05600|07400|01500|00132|01731)[-_a-z0-9]*\.cl$/.test(name));
  // Batch-3 archive kernels: WinZip and PKZIP are pure-only; 7-Zip also has
  // the suffix-less optimized kernel.
  dirFiles("OpenCL", (name) =>
    /^m(11600|13600|17200|17210)[-a-z0-9_]*\.cl$/.test(name));
  // Batch-4 document kernels: Office 2007/2013 and PDF 1.4-1.6 are pure-only;
  // oldoffice and PDF 1.1-1.3 ship optimized-only kernel families.
  dirFiles("OpenCL", (name) =>
    /^m(09400|09600|09700|10400|10500)[-a-z0-9_]*\.cl$/.test(name));
  // Batch-5 wallet kernels: all four wallet modes are pure-only.
  dirFiles("OpenCL", (name) =>
    /^m(11300|13400|15600|15700)[-a-z0-9_]*\.cl$/.test(name));
  // Batch-6 kernels: Kerberos modes ship optimized + pure families,
  // BitLocker is pure-only.
  dirFiles("OpenCL", (name) =>
    /^m(13100|18200|22100)[-a-z0-9_]*\.cl$/.test(name));
  // Apple Metal/OpenCL extension sources pinned for macOS runtime parity.
  add("src/ext_metal.m");
  add("src/ext_iokit.m");
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

  // No overwriting a local modification silently when re-importing. A local
  // file that already matches the pinned manifest (CyberDeck loader patches
  // are part of the pinned provenance) is accepted as up to date.
  const previous = (() => {
    try { return JSON.parse(readFileSync(fileManifest, "utf8")); } catch { return { files: {} }; }
  })();
  const paths = Array.from(entries).sort();
  for (const rel of paths) {
    const data = readFileSync(file(rel));
    const target = resolve(vendor, rel);
    if (existsSync(target) && hash(readFileSync(target)) !== hash(data)) {
      const pinned = previous.files?.[rel];
      if (!pinned || pinned.sha256 !== hash(readFileSync(target))) {
        throw new Error("local vendor differs; refusing destructive overwrite: " + rel);
      }
    }
  }
  for (const rel of paths) {
    const target = resolve(vendor, rel);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(file(rel), target);
  }
  // CyberDeck loader patches, applied identically on every import so the
  // manifest pins the patched bytes. (1) dynloader: resolve module-plugin
  // dependencies from the plugin's own directory. (2) folder: register the
  // install root and preload the shared core before plugins load.
  const NL = String.fromCharCode(10);
  {
    const dyn = resolve(vendor, "src/dynloader.c");
    let text = readFileSync(dyn, "utf8");
    const dynAnchor = "hc_dynlib_t hc_dlopen (LPCSTR lpLibFileName)" + NL + "{" + NL + "  return LoadLibraryA (lpLibFileName);" + NL + "}";
    const dynPatch = "hc_dynlib_t hc_dlopen (LPCSTR lpLibFileName)" + NL + "{" + NL + "  /* CyberDeck: module DLLs live in a subfolder and import hashcat.dll from" + NL + "   * the install root; resolve dependencies from the plugin's own folder. */" + NL + "  #if defined (_WIN)" + NL + "  return LoadLibraryExA (lpLibFileName, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);" + NL + "  #else" + NL + "  return LoadLibraryA (lpLibFileName);" + NL + "  #endif" + NL + "}";
    if (!text.includes("LoadLibraryExA")) {
      if (!text.includes(dynAnchor)) throw new Error("dynloader anchor missing upstream");
      writeFileSync(dyn, text.replace(dynAnchor, dynPatch));
    }
    const fold = resolve(vendor, "src/folder.c");
    let ftext = readFileSync(fold, "utf8");
    const foldAnchor = "int folder_config_init (hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const char *install_folder, MAYBE_UNUSED const char *shared_folder)" + NL + "{";
    const foldPatch = "int folder_config_init (hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const char *install_folder, MAYBE_UNUSED const char *shared_folder)" + NL + "{" + NL + "  /* CyberDeck: module DLLs import hashcat.dll from the install root;" + NL + "   * register the root and preload the core so plugins resolve it. */" + NL + "  #if defined (_WIN)" + NL + "  if (install_folder != NULL)" + NL + "  {" + NL + "    SetDllDirectoryA (install_folder);" + NL + "    char core_dll[HCBUFSIZ_TINY];" + NL + '    snprintf (core_dll, sizeof (core_dll), "%s%s", install_folder, "hashcat.dll");' + NL + "    LoadLibraryA (core_dll);" + NL + "  }" + NL + "  #endif";
    if (!ftext.includes("SetDllDirectoryA")) {
      if (!ftext.includes(foldAnchor)) throw new Error("folder anchor missing upstream");
      writeFileSync(fold, ftext.replace(foldAnchor, foldPatch));
    }
  }
  // Hash the PATCHED local vendor bytes: CyberDeck loader patches are part
  // of the pinned provenance, applied identically on every import.
  const files = Object.fromEntries(paths.map((rel) => {
    const data = readFileSync(resolve(vendor, rel));
    return [rel, { sha256: hash(data), bytes: data.length }];
  }));
  writeFileSync(fileManifest, JSON.stringify({
    schema: 1,
    upstream: "https://github.com/hashcat/hashcat",
    commit: pin,
    version: "v8.0.0-development",
    build: "SHARED=1 PRODUCTION=1 ENABLE_BRAIN=0 ENABLE_CUBIN=0; module_00000 bootstrap + module_01400",
    supportedModesPlanned: [1400],
    includes: ["C core Makefile object closure", "all public and internal C headers", "host EMU kernel includes", "SHA-256 kernels and amplifiers", "batch-1 KDF kernels (phpass/md5crypt/sha512crypt/bcrypt)", "batch-3 archive kernels (7z/WinZip/PKZIP)", "OpenCL headers", "sse2neon compatibility", "runtime tunings", "licenses"],
    excludes: ["standalone hashcat CLI", "hash modules beyond the bundled batch-3 set (0,10,20,50,60,100,110,120,132,400,500,1000,1100,1400,1500,1700,1731,1800,2100,3200,5500,5600,7400,11600,13600,17200,17210)", "other mode kernels", "Python", "FPGA", "unused bridges and feeds", "docs/examples/test suites"],
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

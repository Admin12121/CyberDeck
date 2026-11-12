#!/usr/bin/env node
// CyberDeck John the Ripper source vendor/verify tool.
// The research reference is NEVER read by a normal production build.
// Usage: node apps/desktop/src-tauri/src/third_party/john/vendor.mjs --import
//        node apps/desktop/src-tauri/src/third_party/john/vendor.mjs --verify
//
// Provenance: reference/john is the pristine pin (openwall/john at commit
// JTR_PIN below). The working copy under upstream/ carries only what the
// proven mingw build needs (src sources incl. the subdirectories make and
// configure actually read, run/john.conf, run/rules, and the upstream
// LICENSE file); everything else stays in the reference pin.
//
// Byte fidelity — why this reads git objects, not the working tree:
// Unlike hashcat's vendor.mjs (which copies reference working-tree files),
// the reference/john clone has core.autocrlf=true, so most tracked text
// files sit on disk with CRLF, while the proven C:\Dev\john-build sandbox
// was built from the LF bytes committed in git (verified in-session: the
// sandbox src/configure is byte-identical to `git show HEAD:src/configure`
// and a CRLF configure breaks under /bin/sh). --import therefore extracts
// the pinned commit's raw blobs via `git cat-file --batch` so the manifest
// pins exactly the bytes the proven build consumed. One CyberDeck patch
// (src/path.c
// mingw stubs) is applied identically on every import so the manifest pins
// the patched bytes, mirroring hashcat's loader-patch pattern. The
// sandbox's patched path.c was CRLF-based (autocrlf checkout); the patch
// here is applied to the LF blob and its result was proven equal to the
// sandbox file after EOL normalization.
//
// The build script (build-john.mjs) verifies every manifest entry before it
// stages the tree, and it must be run from an @-FREE path — see the banner
// in build-john.mjs for the MSYS2 '@'-path poison rule.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve, dirname, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../../../../../..");
const reference = resolve(repo, "reference/john");
const vendor = resolve(here, "upstream");
const fileManifest = resolve(here, "source-manifest.json");
const JTR_PIN = "5184bc0b8c105f8c5978b112e723d65b2de3e63e";
const JTR_VERSION = "1.9.0-Jumbo-1-1959-g5184bc0b8";
const mode = process.argv[2];
if (mode !== "--import" && mode !== "--verify") {
  console.error("usage: node apps/desktop/src-tauri/src/third_party/john/vendor.mjs --import|--verify");
  process.exit(2);
}
const hash = (data) => createHash("sha256").update(data).digest("hex");
// Every git read runs with autocrlf/eol forced off: the reference clone has
// core.autocrlf=true, and `git archive` applies the same CRLF smudge as a
// checkout, which would poison the pinned bytes (observed in-session: the
// first import produced CRLF path.c and the patch anchors stopped matching).
const git = (args) => execFileSync("git",
  ["-c", "core.autocrlf=false", "-c", "core.eol=lf", "-C", reference, ...args], { maxBuffer: 1 << 28 });

// The vendored set: src top level plus the subdirectories the proven UCRT64
// mingw build reads (configure compiles CL/cl.h probes from src/, make links
// lzma/, yescrypt/, mbedtls/, secp256k1/, ed25519-donna/, poly1305-donna/).
// Excluded from the pin (present only in reference/john): m4/ (autoconf
// regeneration; src/configure is already generated), tests/ (unit-test
// target the proven make does not build), unused/ (dead formats), packaging/
// (release tooling), Unicode/ (regeneration data for the pre-generated
// encoding_data.h), ztex/ (FPGA host code, not built without ZTEX support).
const SRC_SUBDIRS = new Set(["CL", "ed25519-donna", "lzma", "mbedtls", "poly1305-donna", "secp256k1", "yescrypt"]);

// src/path.c CyberDeck mingw patch — anchors validated in-session to
// reproduce the proven sandbox patch result exactly (byte-identical after
// EOL normalization; the sandbox copy was CRLF-based from the autocrlf
// checkout). Declared before the mode logic: the import path uses it.
const T = String.fromCharCode(9);
const NL = String.fromCharCode(10);
const JTR_PATH_PATCHES = [
  {
    // mingw has no POSIX pwd.h: declare the minimal struct locally.
    before: "#include <errno.h>" + NL + "#include <pwd.h>" + NL + "#include <sys/types.h>",
    after: "#include <errno.h>" + NL + "#ifdef __MINGW32__" + NL + "#include <direct.h>" + NL +
      "/* mingw-w64: no POSIX pwd.h; ~ expansion against the passwd database is" + NL +
      " * a POSIX-only feature in john. The mingw build gets a no-op stub. */" + NL +
      "struct passwd { char *pw_name; char *pw_dir; char *pw_shell; };" + NL +
      "#else" + NL + "#include <pwd.h>" + NL + "#endif" + NL + "#include <sys/types.h>",
    count: 1,
  },
  {
    // mingw has no passwd database: HOME / the systemwide home wins.
    before: T + 'if (!(home_dir = getenv("HOME"))) {' + NL + T + T + "struct passwd *pw;" + NL + NL +
      T + T + "pw = getpwuid(getuid());" + NL + T + T + "endpwent();" + NL + T + T + "if (!pw)" + NL +
      T + T + T + "return;" + NL + T + T + "home_dir = pw->pw_dir;" + NL,
    after: T + 'if (!(home_dir = getenv("HOME"))) {' + NL + "#ifdef __MINGW32__" + NL +
      T + T + "/* mingw: no POSIX passwd database; HOME/systemwide home wins. */" + NL + T + T + "return;" + NL +
      "#else" + NL + T + T + "struct passwd *pw;" + NL + NL + T + T + "pw = getpwuid(getuid());" + NL +
      T + T + "endpwent();" + NL + T + T + "if (!pw)" + NL + T + T + T + "return;" + NL +
      T + T + "home_dir = pw->pw_dir;" + NL + "#endif" + NL,
    count: 1,
  },
  {
    // mingw: mkdir(2) is _mkdir(3) from <direct.h> (mode-less).
    before: T + "if (mkdir(private, S_IRUSR | S_IWUSR | S_IXUSR)) {" + NL +
      T + T + 'if (errno != EEXIST) pexit("mkdir: %s", private);' + NL +
      T + "} else" + NL + T + T + 'fprintf(stderr, "Created directory: %s\\n", private);' + NL,
    after: "#ifdef __MINGW32__" + NL + T + "if (_mkdir(private)) {" + NL +
      T + T + 'if (errno != EEXIST) pexit("mkdir: %s", private);' + NL +
      T + "} else" + NL + T + T + 'fprintf(stderr, "Created directory: %s\\n", private);' + NL +
      "#else" + NL +
      T + "if (mkdir(private, S_IRUSR | S_IWUSR | S_IXUSR)) {" + NL +
      T + T + 'if (errno != EEXIST) pexit("mkdir: %s", private);' + NL +
      T + "} else" + NL + T + T + 'fprintf(stderr, "Created directory: %s\\n", private);' + NL +
      "#endif" + NL,
    count: 2,
  },
];

// Raw blob extractor over one `git cat-file --batch` process: request every
// needed path as "<pin>:<path>", parse the "<oid> blob <size>" framing and
// collect the exact committed bytes. Function declaration: hoisted for the
// import path.
function extractBlobs(paths) {
  const requests = paths.map((path) => JTR_PIN + ":" + path + "\n").join("");
  const out = execFileSync("git",
    ["-c", "core.autocrlf=false", "-c", "core.eol=lf", "-C", reference, "cat-file", "--batch", "--buffer"],
    { input: requests, maxBuffer: 1 << 28 });
  const blobs = new Map();
  let offset = 0;
  for (const path of paths) {
    let nl = out.indexOf(0x0a, offset);
    if (nl < 0) throw new Error("cat-file batch truncated at " + path);
    const header = out.subarray(offset, nl).toString("utf8");
    const parts = header.split(" ");
    if (parts.length !== 3 || parts[1] !== "blob" || !/^\d+$/.test(parts[2])) {
      throw new Error("cat-file failed for " + path + ": " + header);
    }
    const size = parseInt(parts[2], 10);
    const data = out.subarray(nl + 1, nl + 1 + size);
    if (out[nl + 1 + size] !== 0x0a) throw new Error("cat-file framing corrupt for " + path);
    blobs.set(path, data);
    offset = nl + 1 + size + 1;
  }
  return blobs;
}

if (mode === "--import") {
  // Prove the pin exists in the reference clone before touching upstream/.
  git(["rev-parse", "--verify", JTR_PIN + "^{commit}"]);
  // Enumerate the needed set from the pinned tree itself (not the working
  // tree index), then extract exactly those blobs.
  const tracked = git(["ls-tree", "-r", "--name-only", "-z", JTR_PIN, "--", "src", "run", "LICENSE"])
    .toString().split("\0").filter(Boolean);
  const needed = new Set();
  for (const path of tracked) {
    const rel = path.slice("src/".length);
    if (path === "LICENSE" || path === "run/john.conf" || path.startsWith("run/rules/")) {
      needed.add(path);
    } else if (path.startsWith("src/")) {
      if (!rel.includes("/") || SRC_SUBDIRS.has(rel.split("/")[0])) needed.add(path);
    }
  }
  if (needed.size < 800 || !needed.has("src/configure") || !needed.has("src/Makefile.in") ||
      !needed.has("run/john.conf") || !needed.has("LICENSE")) {
    throw new Error("vendored set sanity check failed (" + needed.size + " entries)");
  }
  // Extract the pinned blobs. `git cat-file --batch` streams raw committed
  // bytes in one process — unlike `git archive` it never applies CRLF
  // smudging, export-ignore or export-subst (archive rewrote Makefile.in's
  // literal "$Format:-%h %ci$" version placeholder in-session, which would
  // have changed the built version string).
  const blobs = extractBlobs(Array.from(needed));
  // No silent overwrite of a local deviation when re-importing; a file that
  // already matches the pinned manifest (the path.c CyberDeck patch is part
  // of the pinned provenance) is accepted as up to date.
  const previous = (() => {
    try { return JSON.parse(readFileSync(fileManifest, "utf8")); } catch { return { files: {} }; }
  })();
  for (const path of needed) {
    const data = blobs.get(path);
    if (!data) throw new Error("pinned file missing from cat-file output: " + path);
    const target = resolve(vendor, path);
    if (existsSync(target) && !readFileSync(target).equals(data)) {
      const pinned = previous.files?.[path];
      if (!pinned || pinned.sha256 !== hash(readFileSync(target))) {
        throw new Error("local vendor differs; refusing destructive overwrite: " + path);
      }
    }
  }
  for (const path of needed) {
    const target = resolve(vendor, path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, blobs.get(path));
  }
  // CyberDeck mingw stubs for src/path.c, applied identically on every
  // import so the manifest pins the patched bytes. Each anchor must occur
  // exactly `count` times in the pristine blob; a re-import of an already
  // patched tree is caught by the overwrite guard above (patched bytes
  // match the previous manifest) and leaves the file untouched.
  const pathC = resolve(vendor, "src/path.c");
  let text = readFileSync(pathC, "utf8");
  for (const { before, after, count } of JTR_PATH_PATCHES) {
    const parts = text.split(before);
    if (parts.length - 1 !== count) {
      throw new Error("path.c patch anchor matched " + (parts.length - 1) +
        " times, expected " + count + " — upstream drift");
    }
    text = parts.join(after);
  }
  writeFileSync(pathC, text, "utf8");
  // Hash the PATCHED vendor bytes: the CyberDeck patch is part of the
  // pinned provenance, applied identically on every import.
  const files = Object.fromEntries(Array.from(needed).sort().map((path) => {
    const data = readFileSync(resolve(vendor, path));
    return [path, { sha256: hash(data), bytes: data.length }];
  }));
  writeFileSync(fileManifest, JSON.stringify({
    schema: 1,
    upstream: "https://github.com/openwall/john",
    commit: JTR_PIN,
    version: JTR_VERSION,
    build: "mingw-w64 UCRT64 (gcc 16.2.0) configure + make; john.exe object closure linked as john.dll via native/cd_john_shim.c",
    includes: [
      "src top level (all formats, core, headers, pre-generated configure/Makefile.in/autoconfig.h.in)",
      "src subdirectories configure or make read: CL (OpenCL probe headers), lzma, yescrypt, mbedtls, secp256k1, ed25519-donna, poly1305-donna",
      "run/john.conf and run/rules (pinned runtime configuration)",
      "upstream LICENSE (GPLv2 boilerplate as shipped by john)",
    ],
    excludes: [
      "m4/ (autoconf regeneration; src/configure is pre-generated and pinned)",
      "tests/ (unit-test target the proven make does not build)",
      "unused/ (dead format sources never compiled)",
      "packaging/ (release tooling)",
      "Unicode/ (regeneration data for the pre-generated encoding_data.h)",
      "ztex/ (FPGA bitstream host code, not built without ZTEX support)",
      "all other run/ contents (2john helpers, charsets, wordlists) beyond john.conf + rules",
    ],
    patches: ["src/path.c: mingw-w64 stubs — no POSIX pwd.h/getpwuid/mkdir(2) on UCRT64; no-op passwd expansion and _mkdir(3) under __MINGW32__"],
    files,
  }, null, 2) + "\n");
  console.log("Imported " + needed.size + " pinned source/config/license files from commit " + JTR_PIN.slice(0, 10) + " (path.c patched).");
} else {
  const manifest = JSON.parse(readFileSync(fileManifest, "utf8"));
  if (manifest.commit !== JTR_PIN || manifest.schema !== 1) throw new Error("upstream provenance mismatch");
  let total = 0;
  for (const [rel, info] of Object.entries(manifest.files)) {
    const path = resolve(vendor, rel);
    if (!path.startsWith(vendor + sep)) throw new Error("unsafe manifest path");
    const data = readFileSync(path);
    if (data.length !== info.bytes || hash(data) !== info.sha256) throw new Error("vendored source altered: " + rel);
    total += data.length;
  }
  console.log("Verified " + Object.keys(manifest.files).length + " vendored files, " + total + " bytes, commit " + JTR_PIN);
}

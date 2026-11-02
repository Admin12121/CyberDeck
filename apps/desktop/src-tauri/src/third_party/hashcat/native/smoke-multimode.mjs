#!/usr/bin/env node
/**
 * Controlled private-worker KAT for selected bundled Hashcat raw-digest modes.
 * Does not use a separately installed Hashcat executable or print any secret.
 * Usage: node smoke-multimode.mjs --runtime /absolute/bundle [--mode all|md5|sha1|sha256|sha512]
 * Hardware acceptance is only proven if the worker returns and the independent
 * digest check succeeds on the actual operator's host.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, isAbsolute } from "node:path";

const opts = process.argv.slice(2);
const runtimeArg = opts.indexOf("--runtime");
const modeArg = opts.indexOf("--mode");
if (runtimeArg < 0 || runtimeArg + 1 >= opts.length ||
    (opts.length !== 2 && opts.length !== 4) ||
    (opts.length === 4 && (modeArg < 0 || modeArg + 1 >= opts.length))) {
  throw new Error("usage: --runtime /absolute/runtime [--mode all|md5|sha1|sha256|sha512]");
}
const runtime = opts[runtimeArg + 1];
if (!isAbsolute(runtime) || Buffer.byteLength(runtime) > 4096) {
  throw new Error("Hashcat runtime must be a bounded absolute path");
}
const modes = { md5: 0, sha1: 100, sha256: 1400, sha512: 1700 };
const selected = modeArg < 0 ? "all" : opts[modeArg + 1];
if (selected !== "all" && !(selected in modes)) {
  throw new Error("unsupported controlled KAT hash mode");
}
const worker = join(runtime, process.platform === "win32"
  ? "cyberdeck-recovery-worker.exe" : "cyberdeck-recovery-worker");
if (!statSync(worker).isFile()) throw new Error("bundled private worker is missing");
const fixture = Buffer.from("cyberdeck-embedded-controlled-known-answer", "utf8");
const algorithms = selected === "all" ? Object.keys(modes) : [selected];

function packet(pathList, mode) {
  const limits = Buffer.alloc(20);
  limits.writeBigUInt64LE(3n, 0);
  limits.writeUInt32LE(45, 8);
  limits.writeUInt32LE(0, 12);
  limits.writeUInt32LE(modes[mode], 16);
  const fields = pathList.map(path => {
    const raw = Buffer.from(path, "utf8");
    if (!isAbsolute(path) || !raw.length || raw.length > 4096) {
      throw new Error("invalid bounded private-worker path");
    }
    const size = Buffer.alloc(2);
    size.writeUInt16LE(raw.length);
    return Buffer.concat([size, raw]);
  });
  return Buffer.concat([Buffer.from("CDHC0002"), limits, ...fields]);
}

for (const mode of algorithms) {
  const scratch = mkdtempSync(join(tmpdir(), "cyberdeck-embedded-kat-"));
  const home = join(scratch, "home");
  const target = join(scratch, "digest.hex");
  const wordlist = join(scratch, "wordlist.txt");
  const outfile = join(scratch, "recovery.tmp");
  try {
    mkdirSync(home, { mode: 0o700 });
    const expected = createHash(mode).update(fixture).digest();
    writeFileSync(target, expected.toString("hex") + "\n", { mode: 0o600 });
    writeFileSync(wordlist, "incorrect\n" + fixture.toString("utf8") + "\nother-wrong\n", { mode: 0o600 });
    const child = spawnSync(worker, [], {
      input: packet([runtime, target, wordlist, outfile], mode),
      cwd: home, timeout: 75_000, maxBuffer: 4096,
      env: { ...process.env, HOME: home, XDG_CACHE_HOME: home,
        XDG_CONFIG_HOME: home, APPDATA: home, LOCALAPPDATA: home,
        TMP: home, TEMP: home },
      stdio: ["pipe", "ignore", "ignore"],
    });
    if (child.error || child.status !== 0) {
      throw new Error("embedded native KAT did not complete for mode " + modes[mode] +
        " (worker status " + (child.status ?? "unavailable") + ")");
    }
    const raw = readFileSync(outfile);
    if (!raw.length || raw.length > 4096) throw new Error("invalid private result length");
    let end = raw.length;
    if (raw[end - 1] === 10) end--;
    if (end && raw[end - 1] === 13) end--;
    const candidate = raw.subarray(0, end);
    const digest = createHash(mode).update(candidate).digest();
    if (!timingSafeEqual(digest, expected) || !candidate.equals(fixture)) {
      throw new Error("embedded recovered candidate failed independent digest verification");
    }
    process.stdout.write("PASS: Hashcat native mode " + modes[mode] + " known-answer execution\n");
  } finally {
    rmSync(scratch, { recursive: true, force: true, maxRetries: 3 });
  }
}

#!/usr/bin/env node
/**
 * CyberDeck pinned embedded John the Ripper source build.
 * SPDX-License-Identifier: MIT
 *
 * ════════════════════════════════════════════════════════════════════════
 *  THE @-PATH POISON RULE — READ THIS BEFORE MOVING ANYTHING
 * ════════════════════════════════════════════════════════════════════════
 *  configure + make + gcc MUST run from a path that contains NO "@" and NO
 *  whitespace. The CyberDeck checkout itself lives at
 *  C:\Dev\admin12121\@26\HackTool — the "@26" segment is exactly why the
 *  proven mingw build was sandboxed OUTSIDE the repo (C:\Dev\john-build)
 *  instead of in-place: '@' is meaningful to the MSYS2/autotools/make tool
 *  chain (Makefile silent-command prefix, @response-file arguments, shell
 *  expansion) and an @-bearing build path was never proven. This script
 *  therefore stages the vendored tree under --out and hard-fails if the
 *  staging path (or the -I path it injects into the generated Makefile)
 *  contains "@" or whitespace. Reading the vendored sources from the repo
 *  with node is safe — only the configure/make workspace must be @-free.
 * ════════════════════════════════════════════════════════════════════════
 *
 * Replays the proven mingw-w64 UCRT64 recipe (sandbox C:\Dev\john-build,
 * 2025-11-12): stage pinned sources, verify hashes, run ./configure, apply
 * the seven proven post-configure misdetection fixes to autoconfig.h plus
 * the three proven Makefile flag insertions, build with make -j16, compile
 * the CyberDeck DLL shim, and link the exact proven john.exe object closure
 * as john.dll. Installs john.dll + the msys-2.0.dll runtime beside the app
 * (john.exe is replaced by the DLL for the embedded FFI; no CLI is shipped).
 *
 * Does NOT build or execute a john CLI for users, fetch anything, access the
 * ignored reference/ directory, touch resources/hashcat, or alter Cargo.
 *
 * npm/node are already available for CyberDeck's Next.js/Tauri frontend.
 * Usage (run from any directory; --out must be @-free):
 *   node apps/desktop/src-tauri/src/third_party/john/build-john.mjs --out C:/Dev/cyberdeck-john-build [--install apps/desktop/src-tauri/resources/engines]
 *
 * The integration owner calls this from the normal desktop build flow (a
 * GPU-free window is NOT required — john is CPU-only, but the first full
 * build takes several minutes). Prerequisites: MSYS2 with the UCRT64
 * environment and mingw-w64-ucrt-x86_64-openssl installed, plus Node.js.
 */
import { readFileSync, writeFileSync, copyFileSync, mkdirSync, cpSync, existsSync, statSync, readdirSync, rmSync } from "node:fs";
import { dirname, resolve, join, sep, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

const root = dirname(fileURLToPath(import.meta.url));
const source = join(root, "upstream");
const manifestPath = join(root, "source-manifest.json");
const native = join(root, "native");
const JTR_PIN = "5184bc0b8c105f8c5978b112e723d65b2de3e63e";
const PROVEN_VERSION_H = "#define JTR_GIT_VERSION JUMBO_VERSION \"-$\"";
// The exact object closure of the proven ../run/john.exe link (sandbox
// C:\Dev\john-build\src\link-dll.sh, make-finish9.log 2025-11-12 23:45),
// extracted verbatim; ../compat/stpcpy.o is its last entry by position.
const PROVEN_OBJECTS = [
  "jumbo.o", "john_mpi.o", "DES_fmt.o", "DES_std.o", "DES_bs.o", "DES_bs_b.o",
  "BSDI_fmt.o", "MD5_fmt.o", "MD5_std.o", "md5crypt_common.o", "md5crypt_long_fmt.o", "BF_fmt.o",
  "BF_std.o", "BF_common.o", "scrypt_fmt.o", "yescrypt/yescrypt-opt.o", "yescrypt/yescrypt-common.o", "yescrypt/sha256.o",
  "AFS_fmt.o", "LM_fmt.o", "trip_fmt.o", "KeccakDuplex.o", "KeccakF-1600-opt64.o", "KeccakHash.o",
  "KeccakSponge.o", "whirlpool.o", "haval.o", "skein.o", "md2.o", "panama.o",
  "timer.o", "omp_autotune.o", "md5.o", "rc4.o", "hmacmd5.o", "base64_convert.o",
  "md4.o", "sha1.o", "sha2.o", "dynamic_fmt.o", "dynamic_parser.o", "dynamic_preloads.o",
  "dynamic_utils.o", "dynamic_big_crypt.o", "dynamic_compiler.o", "dynamic_compiler_lib.o", "ripemd.o", "tiger.o",
  "unrarcmd.o", "unrarfilter.o", "unrarhlp.o", "unrar.o", "unrarppm.o", "unrarvm.o",
  "rar2john.o", "zip2john.o", "pkzip.o", "7z_common_plug.o", "7z_fmt_plug.o", "adxcrypt_fmt_plug.o",
  "aes_ccm_plug.o", "aes_gcm_plug.o", "aes_ige_plug.o", "agilekeychain_common_plug.o", "agilekeychain_fmt_plug.o", "aix_ssha_fmt_plug.o",
  "andotp_fmt_plug.o", "androidbackup_common_plug.o", "androidbackup_fmt_plug.o", "androidfde_fmt_plug.o", "ansible_common_plug.o", "ansible_fmt_plug.o",
  "argon2_core_plug.o", "argon2_encoding_plug.o", "argon2_fmt_plug.o", "argon2_opt_plug.o", "argon2_plug.o", "argon2_ref_plug.o",
  "armory_fmt_plug.o", "as400_des_fmt_plug.o", "as400_ssha1_fmt_plug.o", "asaMD5_fmt_plug.o", "asn1_plug.o", "axcrypt_common_plug.o",
  "axcrypt_fmt_plug.o", "AzureAD_common_plug.o", "AzureAD_fmt_plug.o", "bcrypt_pbkdf_plug.o", "bestcrypt_fmt_plug.o", "bestcrypt_ve_fmt_plug.o",
  "BFEgg_fmt_plug.o", "bitcoin_fmt_plug.o", "bitlocker_common_plug.o", "bitlocker_fmt_plug.o", "bitshares_fmt_plug.o", "bitwarden_common_plug.o",
  "bitwarden_fmt_plug.o", "bks_fmt_plug.o", "blackberry_ES10_fmt_plug.o", "blake256_plug.o", "blake2b_plug.o", "blake2b-ref_plug.o",
  "blf_plug.o", "blockchain_common_plug.o", "blockchain_fmt_plug.o", "cardano_common_plug.o", "cardano_fmt_plug.o", "chacha_plug.o",
  "chap_fmt_plug.o", "citrix_ns_fmt_plug.o", "clipperz_srp_fmt_plug.o", "cloudkeychain_common_plug.o", "cloudkeychain_fmt_plug.o", "cmac_plug.o",
  "cq_fmt_plug.o", "crc32_fmt_plug.o", "cryptosafe_common_plug.o", "cryptosafe_fmt_plug.o", "dahua_fmt_plug.o", "dashlane_common_plug.o",
  "dashlane_fmt_plug.o", "diskcryptor_common_plug.o", "diskcryptor_fmt_plug.o", "django_fmt_plug.o", "django_scrypt_fmt_plug.o", "DMD5_fmt_plug.o",
  "dmg_common_plug.o", "dmg_fmt_plug.o", "DOMINOSEC_fmt_plug.o", "DOMINOSEC8_fmt_plug.o", "dpapimk_fmt_plug.o", "dragonfly3_fmt_plug.o",
  "dragonfly4_fmt_plug.o", "drupal7_fmt_plug.o", "dynamic_compiler_fmt_plug.o", "ecryptfs_fmt_plug.o", "eigrp_fmt_plug.o", "electrum_fmt_plug.o",
  "encdatavault_common_plug.o", "encdatavault_md5_fmt_plug.o", "encdatavault_pbkdf2_fmt_plug.o", "encfs_common_plug.o", "encfs_fmt_plug.o", "enpass_common_plug.o",
  "enpass_fmt_plug.o", "EPI_fmt_plug.o", "episerver_fmt_plug.o", "ethereum_common_plug.o", "ethereum_fmt_plug.o", "feal8_plug.o",
  "FG2_fmt_plug.o", "FGT_fmt_plug.o", "formspring_fmt_plug.o", "fvde_common_plug.o", "fvde_fmt_plug.o", "geli_common_plug.o",
  "geli_fmt_plug.o", "gost_fmt_plug.o", "gost12256hash_fmt_plug.o", "gost12512hash_fmt_plug.o", "gost3411-2012-core_plug.o", "gost94hash_fmt_plug.o",
  "gpg_common_plug.o", "gpg_fmt_plug.o", "groestl_plug.o", "h3c_fmt_plug.o", "has160_fmt_plug.o", "has160_plug.o",
  "haval_fmt_plug.o", "HDAA_fmt_plug.o", "hmac_sha_plug.o", "hmacMD5_fmt_plug.o", "hmacSHA1_fmt_plug.o", "hmacSHA256_fmt_plug.o",
  "hmacSHA512_fmt_plug.o", "hmailserver_fmt_plug.o", "hsrp_fmt_plug.o", "idea_plug.o", "ike_fmt_plug.o", "IPB2_fmt_plug.o",
  "iterated_sha1_common_plug.o", "iterated_sha1_fmt_plug.o", "iterated_sha256_common_plug.o", "iterated_sha256_fmt_plug.o", "itunes_common_plug.o", "itunes_fmt_plug.o",
  "iwork_common_plug.o", "iwork_fmt_plug.o", "jh_plug.o", "keccak_plug.o", "keepass_common_plug.o", "keepass_fmt_plug.o",
  "keplr_fmt_plug.o", "keychain_common_plug.o", "keychain_fmt_plug.o", "keyring_fmt_plug.o", "keystore_common_plug.o", "keystore_fmt_plug.o",
  "known_hosts_fmt_plug.o", "KRB4_fmt_plug.o", "KRB4_std_plug.o", "krb5_asrep_common_plug.o", "krb5_asrep_fmt_plug.o", "krb5_common_plug.o",
  "krb5_db_fmt_plug.o", "KRB5_fmt_plug.o", "KRB5_std_plug.o", "krb5_tgs_common_plug.o", "krb5_tgs_fmt_plug.o", "krb5_tgsrep_common_plug.o",
  "krb5_tgsrep_fmt_plug.o", "krb5pa-md5_fmt_plug.o", "krb5pa-sha1_fmt_plug.o", "kwallet_fmt_plug.o", "lastpass_cli_common_plug.o", "lastpass_cli_fmt_plug.o",
  "lastpass_common_plug.o", "lastpass_fmt_plug.o", "lastpass_sniffed_fmt_plug.o", "leet_cc_fmt_plug.o", "lotus5_fmt_plug.o", "lotus85_fmt_plug.o",
  "luks_fmt_plug.o", "md2_fmt_plug.o", "mdc2_fmt_plug.o", "mdc2dgst_plug.o", "mediawiki_fmt_plug.o", "monero_fmt_plug.o",
  "money_fmt_plug.o", "mongodb_fmt_plug.o", "mongodb_scram_fmt_plug.o", "mozilla_ng_fmt_plug.o", "mscash_common_plug.o", "mscash1_fmt_plug.o",
  "mscash2_fmt_plug.o", "MSCHAPv2_bs_fmt_plug.o", "mssql05_fmt_plug.o", "mssql12_fmt_plug.o", "mssql-old_fmt_plug.o", "multibit_fmt_plug.o",
  "mysql_fmt_plug.o", "mysql_netauth_fmt_plug.o", "mysqlSHA1_fmt_plug.o", "net_ah_fmt_plug.o", "net_md5_fmt_plug.o", "net_sha1_fmt_plug.o",
  "NETLM_fmt_plug.o", "NETLMv2_fmt_plug.o", "NETNTLM_bs_fmt_plug.o", "NETNTLMv2_fmt_plug.o", "NETSPLITLM_fmt_plug.o", "notes_common_plug.o",
  "notes_fmt_plug.o", "NS_fmt_plug.o", "nsec3_fmt_plug.o", "nt2_fmt_plug.o", "ntlmv1_mschapv2_fmt_plug.o", "NT-long_fmt_plug.o",
  "nukedclan_fmt_plug.o", "o10glogon_fmt_plug.o", "o3logon_fmt_plug.o", "o5logon_common_plug.o", "o5logon_fmt_plug.o", "oaes_lib_plug.o",
  "odf_common_plug.o", "odf_fmt_plug.o", "office_common_plug.o", "office_fmt_plug.o", "oldoffice_common_plug.o", "oldoffice_fmt_plug.o",
  "openbsdsoftraid_common_plug.o", "openbsdsoftraid_fmt_plug.o", "openssl_code_plug.o", "openssl_enc_fmt_plug.o", "oracle_fmt_plug.o", "oracle11_fmt_plug.o",
  "oracle12c_fmt_plug.o", "osc_fmt_plug.o", "ospf_fmt_plug.o", "oubliette_blowfish_fmt_plug.o", "oubliette_idea_fmt_plug.o", "padlock_fmt_plug.o",
  "palshop_fmt_plug.o", "panama_fmt_plug.o", "pbkdf2_hmac_common_plug.o", "pbkdf2_hmac_sha256_fmt_plug.o", "pbkdf2-hmac-md4_fmt_plug.o", "pbkdf2-hmac-md5_fmt_plug.o",
  "pbkdf2-hmac-sha1_fmt_plug.o", "pbkdf2-hmac-sha512_fmt_plug.o", "pdf_common_plug.o", "pdf_fmt_plug.o", "pdfcrack_md5_plug.o", "pem_common_plug.o",
  "pem_fmt_plug.o", "pfx_common_plug.o", "pfx_fmt_plug.o", "pgpdisk_common_plug.o", "pgpdisk_fmt_plug.o", "pgpsda_common_plug.o",
  "pgpsda_fmt_plug.o", "pgpwde_common_plug.o", "pgpwde_fmt_plug.o", "phpass_common_plug.o", "phpassMD5_fmt_plug.o", "PHPS_fmt_plug.o",
  "PHPS2_fmt_plug.o", "pixMD5_fmt_plug.o", "pkcs12_plug.o", "pkzip_fmt_plug.o", "plaintext_fmt_plug.o", "PO_fmt_plug.o",
  "postgres_fmt_plug.o", "pst_fmt_plug.o", "putty_fmt_plug.o", "pwsafe_common_plug.o", "pwsafe_fmt_plug.o", "qnx_fmt_plug.o",
  "racf_fmt_plug.o", "racf_kdfaes_fmt_plug.o", "radius_fmt_plug.o", "radmin_fmt_plug.o", "rakp_md5_fmt_plug.o", "rakp_sha1_fmt_plug.o",
  "rakp_sha256_fmt_plug.o", "rar_fmt_plug.o", "rar5_fmt_plug.o", "rawBLAKE2_512_fmt_plug.o", "rawKeccak_256_fmt_plug.o", "rawKeccak_512_fmt_plug.o",
  "rawMD4_fmt_plug.o", "rawMD5_fmt_plug.o", "rawMD5flat_fmt_plug.o", "rawmd5u_fmt_plug.o", "rawSHA1_common_plug.o", "rawSHA1_fmt_plug.o",
  "rawSHA1_linkedIn_fmt_plug.o", "rawSHA224_fmt_plug.o", "rawSHA256_common_plug.o", "rawSHA256_fmt_plug.o", "rawSHA384_fmt_plug.o", "rawSHA512_common_plug.o",
  "rawSHA512_fmt_plug.o", "rawSM3_fmt_plug.o", "restic_fmt_plug.o", "ripemd_fmt_plug.o", "rsvp_fmt_plug.o", "rvary_fmt_plug.o",
  "salted_sha1_common_plug.o", "salted_sha1_fmt_plug.o", "sap_pse_common_plug.o", "sap_pse_fmt_plug.o", "sapB_fmt_plug.o", "sapG_fmt_plug.o",
  "sapH_fmt_plug.o", "scram_sha256_fmt_plug.o", "securezip_common_plug.o", "securezip_fmt_plug.o", "serpent_plug.o", "sha1crypt_common_plug.o",
  "sha1crypt_fmt_plug.o", "sha256crypt_fmt_plug.o", "sha3_512_fmt_plug.o", "sha512crypt_fmt_plug.o", "siemens-s7_fmt_plug.o", "signal_fmt_plug.o",
  "sip_fmt_plug.o", "skein_fmt_plug.o", "SKEY_fmt_plug.o", "SKEY_jtr_plug.o", "sl3_common_plug.o", "sl3_fmt_plug.o",
  "slow_hash_plug.o", "sm3crypt_fmt_plug.o", "snefru_fmt_plug.o", "snefru_plug.o", "snmp_fmt_plug.o", "solarwinds_common_plug.o",
  "solarwinds_fmt_plug.o", "ssh_common_plug.o", "ssh_fmt_plug.o", "ssha512_fmt_plug.o", "sspr_common_plug.o", "sspr_fmt_plug.o",
  "stribog_fmt_plug.o", "strip_common_plug.o", "strip_fmt_plug.o", "sunmd5_fmt_plug.o", "SybaseASE_fmt_plug.o", "SybasePROP_fmt_plug.o",
  "syb-prop_repro_plug.o", "tacacs_plus_fmt_plug.o", "tcp_md5_fmt_plug.o", "telegram_common_plug.o", "telegram_fmt_plug.o", "tezos_common_plug.o",
  "tezos_fmt_plug.o", "tiger_fmt_plug.o", "timeroast_common_plug.o", "timeroast_fmt_plug.o", "truecrypt_fmt_plug.o", "twofish_plug.o",
  "vdi_fmt_plug.o", "vms_fmt_plug.o", "vmx_common_plug.o", "vmx_fmt_plug.o", "vnc_fmt_plug.o", "vtp_fmt_plug.o",
  "wbb3_fmt_plug.o", "whirlpool_fmt_plug.o", "wow_srp_fmt_plug.o", "wpapmk_fmt_plug.o", "wpapsk_fmt_plug.o", "xmpp_scram_fmt_plug.o",
  "XSHA_fmt_plug.o", "XSHA512_fmt_plug.o", "xts_plug.o", "zed_common_plug.o", "zed_fmt_plug.o", "zip_fmt_plug.o",
  "zipmonster_fmt_plug.o", "dyna_salt.o", "dummy.o", "gost.o", "gpu_common.o", "batch.o",
  "bench.o", "charset.o", "common.o", "compiler.o", "config.o", "cracker.o",
  "crc32.o", "external.o", "formats.o", "getopt.o", "idle.o", "inc.o",
  "john.o", "list.o", "loader.o", "logger.o", "mask.o", "mask_ext.o",
  "memory.o", "misc.o", "options.o", "params.o", "path.o", "recovery.o",
  "rpp.o", "rules.o", "signals.o", "single.o", "status.o", "suppressor.o",
  "tty.o", "wordlist.o", "mkv.o", "mkvlib.o", "subsets.o", "unicode_range.o",
  "listconf.o", "fake_salts.o", "win32_memmap.o", "mmap-windows.o", "uaf_encode.o", "unicode.o",
  "unshadow.o", "unafs.o", "undrop.o", "regex.o", "pp.o", "c3_fmt.o",
  "lzma/LzmaDec.o", "lzma/Lzma2Dec.o", "lzma/Bra.o", "lzma/Bra86.o", "lzma/BraIA64.o", "lzma/CpuArch.o",
  "lzma/Delta.o", "unique.o", "gpg2john.o", "showformats.o", "color.o", "sm3.o",
  "x86-64.o", "simd-intrinsics.o", "../compat/stpcpy.o",
];
const argIndex = process.argv.indexOf("--out");
if (argIndex < 0 || !process.argv[argIndex + 1] || !isAbsolute(process.argv[argIndex + 1])) {
  console.error("usage: node build-john.mjs --out /absolute/@-free/build-output [--install /absolute/resources/engines]");
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

// The @-path poison rule, enforced: every path handed to MSYS2 (the staging
// tree, and therefore everything under --out) must be @-free and space-free.
// The generated Makefile embeds the compat -I path UNQUOTED, so spaces would
// break the compile flags long before configure could complain.
const msysSafe = (p, what) => {
  if (p.includes("@")) throw new Error("@-path poison rule violated for " + what + ": " + p +
    " — configure/make must run from an @-free path (see the banner in this script)");
  if (/\s/.test(p)) throw new Error("whitespace in " + what + " path is unproven for the MSYS2 john build: " + p);
};
msysSafe(output, "--out");
// NOTE: --install is deliberately NOT msysSafe-checked — it is a node-side
// cpSync into resources/engines (which lives under the repo and therefore
// legitimately contains "@"); the poison rule binds only MSYS2-driven steps.

const build = join(output, "build");
const runtime = join(output, "runtime");
const stageSrc = join(build, "src");
const stageCompat = join(build, "compat");
msysSafe(build, "staging tree");
msysSafe(runtime, "runtime tree");

const files = JSON.parse(readFileSync(manifestPath, "utf8"));
if (files.schema !== 1 || files.commit !== JTR_PIN) {
  throw new Error("John provenance revision mismatch");
}
const hash = (data) => createHash("sha256").update(data).digest("hex");
for (const [rel, expected] of Object.entries(files.files)) {
  if (rel.startsWith("/") || rel.split("/").includes("..")) throw new Error("unsafe vendor path");
  const target = resolve(source, rel);
  if (!target.startsWith(source + sep)) throw new Error("vendored path escape");
  const data = readFileSync(target);
  if (data.length !== expected.bytes || hash(data) !== expected.sha256) {
    throw new Error("John vendored file does not match pinned source: " + rel);
  }
}

if (process.platform !== "win32") {
  throw new Error("embedded John build is the proven mingw-w64 UCRT64 recipe; host unsupported: " + process.platform);
}
if (process.env.CARGO_CFG_TARGET_OS && process.env.CARGO_CFG_TARGET_OS !== "windows") {
  throw new Error("cross-compile of embedded John not verified; use matched native target");
}

// Stage the pinned tree with the same refuse-to-mask rule as build-native.mjs.
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
// CyberDeck-native build inputs (all byte-identical to the proven sandbox
// artifacts; they are repo-tracked CyberDeck files, not upstream ones):
//   compat/  — mingw shims the generated Makefile references (-I + ../compat/stpcpy.o)
//   src/pwd.h + src/memmem_shim.h — stubs shadowing POSIX headers MSYS hides
//   src/cd_john_shim.c — the DLL entry shim (compiled and linked at the end)
const nativeStaging = [
  ["compat/getopt.h", "compat/getopt.h"],
  ["compat/stpcpy.c", "compat/stpcpy.c"],
  ["compat/sys/mman.h", "compat/sys/mman.h"],
  ["compat/sys/times.h", "compat/sys/times.h"],
  ["src-pwd.h", "src/pwd.h"],
  ["src-memmem_shim.h", "src/memmem_shim.h"],
  ["cd_john_shim.c", "src/cd_john_shim.c"],
];
for (const [from, to] of nativeStaging) {
  const target = join(build, to);
  mkdirSync(dirname(target), { recursive: true });
  copyFileSync(join(native, from), target);
}

// ── MSYS2 toolchain preflight ─────────────────────────────────────────────
// The proven recipe drives configure/make through a MSYS2 login shell
// (/c/msys64/usr/bin/bash.exe -lc "...") with gcc resolving to the UCRT64
// mingw-w64 compiler (config.log: PATH /usr/bin first, but gcc is the
// x86_64-w64-mingw32 one; an MSYS gcc would answer x86_64-pc-msys and build
// msys-runtime binaries — explicitly not what the proven artifacts are).
const msys2Root = resolve(process.env.JOHN_MSYS2_ROOT || "C:/msys64");
const bashExe = join(msys2Root, "usr", "bin", "bash.exe");
if (!existsSync(bashExe)) {
  throw new Error("MSYS2 bash not found at " + bashExe + " — install MSYS2 or set JOHN_MSYS2_ROOT");
}
// /etc/config.site derives prefix and build_alias from MSYSTEM_PREFIX and
// MSYSTEM_CHOST; the proven config.log shows prefix=/ucrt64, so seed the
// values explicitly when the parent env does not carry them.
const childEnv = {
  ...process.env,
  MSYSTEM_PREFIX: process.env.MSYSTEM_PREFIX || "/ucrt64",
  MSYSTEM_CHOST: process.env.MSYSTEM_CHOST || "x86_64-w64-mingw32",
};
const toMsys = (p) => {
  if (!/^[A-Za-z]:[\\/]/.test(p)) throw new Error("not a drive path for MSYS2 conversion: " + p);
  return "/" + p[0].toLowerCase() + p.slice(2).split("\\").join("/").split("/").filter(Boolean).join("/");
};
function checked(script, label, timeout = 600_000) {
  const z = spawnSync(bashExe, ["-lc", script], {
    cwd: output,
    encoding: "utf8",
    stdio: "pipe",
    timeout,
    env: childEnv,
  });
  if (z.error || z.status !== 0) {
    const tail = ((z.stderr || "") + "\n" + (z.stdout || "")).slice(-8000);
    throw new Error("john build step failed (" + label + "): " + (z.error || "exit " + z.status) + "\n" + tail);
  }
  console.log("john build step accepted: " + label);
}
const msysCompat = toMsys(stageCompat);
// The UCRT64 toolchain identity is load-bearing: an MSYS gcc would answer
// x86_64-pc-msys and build msys-runtime binaries instead of the proven
// ucrt-linked PE artifacts.
{
  const z = spawnSync(bashExe, ["-lc", "gcc -dumpmachine"], { cwd: output, encoding: "utf8", env: childEnv, stdio: "pipe" });
  const machine = (z.stdout || "").trim();
  if (z.status !== 0 || machine !== "x86_64-w64-mingw32") {
    throw new Error("gcc -dumpmachine is '" + machine + "' (exit " + z.status + "), expected x86_64-w64-mingw32 (UCRT64 mingw-w64 gcc). An MSYS gcc would build msys-runtime binaries — see the banner note.");
  }
}
console.log("john build step accepted: UCRT64 gcc toolchain probe");
if (!existsSync(join(msys2Root, "ucrt64", "include", "openssl", "opensslv.h"))) {
  throw new Error("mingw-w64-ucrt-x86_64-openssl is not installed under " + msys2Root + "/ucrt64 (proven prerequisite: openssl 3.6.4)");
}

// ── configure ─────────────────────────────────────────────────────────────
// Proven invocation: plain ./configure with no arguments inside the staged
// src (config.log: "$ ./configure"), via a login shell so /etc/config.site
// and the profile PATH apply exactly as in the sandbox.
checked("cd '" + toMsys(stageSrc) + "' && ./configure", "./configure", 900_000);

// ── proven post-configure fixes ───────────────────────────────────────────
// Seven configure misdetections on UCRT64 were fixed by hand in the proven
// autoconfig.h (raw detections verified in-session against config.log:
// ac_cv_func_posix_memalign=yes, ac_cv_func_mmap=yes, ac_cv_lib_dl_dlopen=yes,
// ac_cv_search_crypt=-lcrypt, ac_cv_header_crypt_h=yes, ARCH_WORD=long).
// Each fix states the raw configure emission and the exact proven final line;
// the patched file is asserted line-for-line against the proven bytes.
const AUTOCONFIG_FIXES = [
  {
    raw: "#define ARCH_WORD long",
    final: "#define ARCH_WORD long long /* jtr mingw: win64 is LLP64 (sizeof(long)==4); configure emitted 'long' which breaks 64-bit DES_bs layout math (xkeys/pxkeys overflow). arch.h's non-AC_BUILT path uses long long for _WIN64 too. */",
    why: "LLP64: sizeof(long)==4 shrank the DES_bs layout so set_key's write formula overflowed xkeys into pxkeys, segfaulting descrypt/bsdicrypt and corrupting LM (proven with gdb)",
  },
  {
    raw: "#define HAVE_POSIX_MEMALIGN 1",
    final: "/* #undef HAVE_POSIX_MEMALIGN */ /* jtr mingw: ucrt64 ld has no posix_memalign symbol (link-verified); use __mingw_aligned_malloc */",
    why: "header declares it but ucrt64 ld has no posix_memalign symbol (link-verified in the sandbox)",
  },
  {
    raw: "/* #undef HAVE___MINGW_ALIGNED_MALLOC */",
    final: "#define HAVE___MINGW_ALIGNED_MALLOC 1 /* jtr mingw: mingwex exports __mingw_aligned_malloc/free; memory.h macro branch pairs alloc+free */",
    why: "mingwex exports __mingw_aligned_malloc/free with a matching memory.h macro branch",
  },
  {
    raw: "#define HAVE_CRYPT 1",
    final: "/* #undef HAVE_CRYPT */ /* jtr mingw: no libcrypt/crypt.h on ucrt64; c3_fmt.c is wholly #if HAVE_CRYPT-guarded */",
    why: "c3_fmt.c is wholly #if HAVE_CRYPT-guarded and the POSIX crypt() ABI is not usable on mingw",
  },
  {
    raw: "#define HAVE_CRYPT_H 1",
    final: "/* #undef HAVE_CRYPT_H */ /* jtr mingw: no crypt.h on ucrt64 */",
    why: "same as HAVE_CRYPT",
  },
  {
    raw: "#define HAVE_LIBDL 1",
    final: "/* #undef HAVE_LIBDL */ /* jtr mingw: no libdl on ucrt64; gpu_common.c dlopen is #if HAVE_LIBDL-guarded */",
    why: "gpu_common.c dlopen path is #if HAVE_LIBDL-guarded",
  },
  {
    raw: "#define HAVE_MMAP 1",
    final: "/* #undef HAVE_MMAP */ /* jtr mingw: no mmap on ucrt64; wordlist/yescrypt fall back to read/malloc paths */",
    why: "wordlist/yescrypt fall back to read/malloc paths",
  },
];
const autoconfigPath = join(stageSrc, "autoconfig.h");
let autoconfig = readFileSync(autoconfigPath, "utf8");
for (const fix of AUTOCONFIG_FIXES) {
  const macro = (fix.raw.match(/^#define (\w+)/) || fix.raw.match(/^\/\* #undef (\w+) \*\//))[1];
  const lines = autoconfig.split("\n");
  // Match the macro's line in either its raw configure-emitted form, its
  // proven fixed form (idempotent re-run over a reused build tree), or its
  // bare template-undef form.
  const hits = lines.map((line, i) => ({ line, i })).filter(({ line }) =>
    line === fix.raw || line === fix.final || line === "/* #undef " + macro + " */");
  if (hits.length !== 1) {
    throw new Error("autoconfig.h fix for " + macro + ": expected exactly 1 matching line, found " + hits.length +
      (hits.length ? ": " + hits.map((h) => JSON.stringify(h.line)).join("; ") : " — configure output drifted from the proven recipe"));
  }
  if (hits[0].line !== fix.final) {
    lines[hits[0].i] = fix.final;
    autoconfig = lines.join("\n");
  }
}
writeFileSync(autoconfigPath, autoconfig);
for (const fix of AUTOCONFIG_FIXES) {
  if (!autoconfig.split("\n").includes(fix.final)) {
    throw new Error("autoconfig.h does not carry the proven " + fix.raw + " fix byte-for-byte");
  }
}
console.log("autoconfig.h: 7 proven misdetection fixes applied (LLP64 ARCH_WORD, aligned malloc, crypt, libdl, mmap)");

// The generated Makefile gets the three proven flag insertions (the sandbox
// Makefile differs from the plain configure emission exactly here; proven
// bytes embedded, with the compat -I path substituted for this staging).
const PROVEN_CPPFLAGS = "CPPFLAGS = -D_GNU_SOURCE -D__CYGWIN32__  -DCL_SILENCE_DEPRECATION";
const PROVEN_CFLAGS_MAIN_TAIL = "-DJOHN_AVX2 -c -g -O2 -DARCH_LITTLE_ENDIAN=1 -DJOHN_SYSTEMWIDE -DJOHN_SYSTEMWIDE_EXEC='\"/ucrt64/bin\"' -DJOHN_SYSTEMWIDE_HOME='\"/ucrt64/share/john\"' -DPREFER_FLOCK -DAC_BUILT  -Wall -std=gnu99 -Wno-stringop-truncation -Wno-format-overflow -Wno-format-truncation -fno-omit-frame-pointer -Wno-deprecated-declarations -Wunused-but-set-variable -Wdate-time -D__USE_MINGW_ANSI_STDIO  -fopenmp   -MMD -MP -MF $(DEPDIR)/$(notdir $*).d $(CPPFLAGS)";
const CFLAGS_MAIN_PREFIX = "-include memmem_shim.h -I" + msysCompat + " -I. -D_GNU_SOURCE -D__CYGWIN32__ ";
const PROVEN_LDFLAGS = "LDFLAGS = -g $(LIBS) ../compat/stpcpy.o";
const makefilePath = join(stageSrc, "Makefile");
let makefile = readFileSync(makefilePath, "utf8");
// Only the targeted line is ever rewritten — the rest of the configure
// emission is left byte-identical (no file-wide whitespace normalization).
const forceLine = (name, prefixMatch, buildExpected) => {
  const lines = makefile.split("\n");
  const idx = lines.findIndex((line) => line.startsWith(prefixMatch));
  if (idx < 0) throw new Error("generated Makefile has no " + name + " line — configure output drifted");
  const expected = buildExpected(lines[idx]);
  if (lines[idx] !== expected) {
    lines[idx] = expected;
    makefile = lines.join("\n");
  }
  if (!makefile.split("\n").includes(expected)) {
    throw new Error("Makefile " + name + " does not match the proven line byte-for-byte: " + expected);
  }
};
forceLine("CPPFLAGS", "CPPFLAGS = ", (raw) =>
  raw.startsWith("CPPFLAGS = -D_GNU_SOURCE")
    ? raw
    : "CPPFLAGS = -D_GNU_SOURCE -D__CYGWIN32__ " + raw.slice("CPPFLAGS = ".length));
forceLine("CFLAGS_MAIN", "CFLAGS_MAIN = ", (raw) => {
  if (raw.startsWith("CFLAGS_MAIN = -include memmem_shim.h")) return raw;
  const value = raw.slice("CFLAGS_MAIN = ".length);
  if (!value.startsWith(PROVEN_CFLAGS_MAIN_TAIL)) {
    throw new Error("generated CFLAGS_MAIN drifted from the proven expansion (AVX2/systemwide flags): " + JSON.stringify(value.slice(0, 120)));
  }
  return "CFLAGS_MAIN = " + CFLAGS_MAIN_PREFIX + value;
});
forceLine("LDFLAGS", "LDFLAGS = ", () => PROVEN_LDFLAGS);
writeFileSync(makefilePath, makefile);
// Proven-state guards on the toolchain resolution inside the generated Makefile.
for (const needle of ["CC = gcc", "prefix = /ucrt64", "-DJOHN_SYSTEMWIDE", "-DJOHN_AVX2"]) {
  if (!makefile.includes(needle)) {
    throw new Error("generated Makefile is missing proven token '" + needle + "' — the MSYS2 environment did not resolve like the sandbox (config.site/MSYSTEM_PREFIX)");
  }
}
console.log("generated Makefile: proven CPPFLAGS/CFLAGS_MAIN/LDFLAGS insertions applied");

// ── compat + full build ───────────────────────────────────────────────────
// compat/stpcpy.o is a CyberDeck file with no Makefile rule (referenced by
// LDFLAGS as ../compat/stpcpy.o); its build flags are the ones its own
// header comment prescribes (-fno-tree-loop-distribute-patterns so gcc -O2
// does not rewrite the copy loop back into a stpcpy call).
checked("cd '" + msysCompat + "' && gcc -c -fno-tree-loop-distribute-patterns -O2 stpcpy.c", "compat/stpcpy.o");
// Proven full build: make -j16 through the MSYS2 login shell.
checked("cd '" + toMsys(stageSrc) + "' && make -j16", "make -j16", 3_600_000);
// In a non-git staging tree the Makefile regenerates version.h with the
// fallback literal — assert the proven version bytes ("1.9.0-jumbo-1+
// bleeding-$" is what --list=build-info printed in the sandbox baseline).
const versionH = readFileSync(join(stageSrc, "version.h"), "utf8").trim();
if (versionH !== PROVEN_VERSION_H) {
  throw new Error("version.h is '" + versionH + "', expected the proven fallback '" + PROVEN_VERSION_H +
    "' — is the staging tree inside a git worktree? Stage @-free outside any repo");
}
// Every object of the proven link closure must exist before linking.
const missingObjects = PROVEN_OBJECTS.filter((o) => !existsSync(join(stageSrc, o)));
if (missingObjects.length) {
  throw new Error("make did not produce " + missingObjects.length + " objects of the proven closure, first: " + missingObjects.slice(0, 8).join(", "));
}
for (const archive of ["mbedtls/aes.a", "secp256k1/secp256k1.a", "ed25519-donna/ed25519-donna.a", "poly1305-donna/poly1305-donna.a"]) {
  if (!existsSync(join(stageSrc, archive))) throw new Error("make did not produce " + archive);
}

// ── shim + DLL link (exact proven command) ────────────────────────────────
// Shim compile flags are the proven ones (DLL track result: gcc -c
// -I<compat> -I. -DAC_BUILT). The link is link-dll.sh verbatim: the exact
// object list of the successful ../run/john.exe link plus cd_john_shim.o,
// with -shared/-static-libgcc and an import library instead of -o john.exe.
checked("cd '" + toMsys(stageSrc) + "' && gcc -c -I" + msysCompat + " -I. -DAC_BUILT cd_john_shim.c", "cd_john_shim.o");
if (!existsSync(join(stageSrc, "cd_john_shim.o"))) throw new Error("shim object missing after compile");
const linkCommand = "cd '" + toMsys(stageSrc) + "' && gcc -shared -static-libgcc cd_john_shim.o " +
  PROVEN_OBJECTS.join(" ") +
  " -g -lws2_32 -lwsock32 -lkernel32 -lssl -lcrypto -fopenmp -lm" +
  " mbedtls/aes.a secp256k1/secp256k1.a ed25519-donna/ed25519-donna.a poly1305-donna/poly1305-donna.a" +
  " -o john.dll -Wl,--out-implib,john.dll.a";
checked(linkCommand, "link john.dll", 900_000);
const dllPath = join(stageSrc, "john.dll");
if (!existsSync(dllPath) || statSync(dllPath).size < 1_000_000) {
  throw new Error("john.dll missing or implausibly small after the proven link");
}

// ── runtime assembly ──────────────────────────────────────────────────────
// Proven dev-runtime layout beside the app: john.dll (+ import library for
// the FFI track), the msys-2.0.dll runtime copy (provenance C:\msys64\usr\bin,
// byte-verified), the pinned john.conf + rules, and the license + manifest.
copyFileSync(dllPath, join(runtime, "john.dll"));
copyFileSync(join(stageSrc, "john.dll.a"), join(runtime, "john.dll.a"));
const msysDll = join(msys2Root, "usr", "bin", "msys-2.0.dll");
if (!existsSync(msysDll)) throw new Error("msys-2.0.dll not found at " + msysDll);
copyFileSync(msysDll, join(runtime, "msys-2.0.dll"));
mkdirSync(join(runtime, "rules"), { recursive: true });
copyFileSync(join(build, "run", "john.conf"), join(runtime, "john.conf"));
for (const name of readdirSync(join(build, "run", "rules"))) {
  copyFileSync(join(build, "run", "rules", name), join(runtime, "rules", name));
}
mkdirSync(join(runtime, "licenses"), { recursive: true });
copyFileSync(join(build, "LICENSE"), join(runtime, "licenses", "JOHN-GPLv2.txt"));
copyFileSync(manifestPath, join(runtime, "source-manifest.json"));
const runtimeChecks = ["john.dll", "john.dll.a", "msys-2.0.dll", "john.conf", "rules",
  "licenses/JOHN-GPLv2.txt", "source-manifest.json"];
for (const name of runtimeChecks) {
  if (!statSync(join(runtime, name)).isFile() && !statSync(join(runtime, name)).isDirectory()) {
    throw new Error("package missing " + name);
  }
}
if (install) {
  mkdirSync(install, { recursive: true });
  cpSync(runtime, install, { recursive: true, force: true });
  // john.exe is replaced by john.dll for the embedded FFI: remove a stale
  // CLI copy so the engine directory holds exactly the DLL runtime.
  const staleExe = join(install, "john.exe");
  if (existsSync(staleExe)) rmSync(staleExe);
  for (const name of runtimeChecks) {
    if (!statSync(join(install, name)).isFile() && !statSync(join(install, name)).isDirectory()) {
      throw new Error("installed package missing " + name);
    }
  }
  console.log("CyberDeck managed John runtime staged for Tauri resources:", install);
}
console.log("Embedded John source-compiled runtime ready:", runtime);
console.log("Pinned upstream:", JTR_PIN.slice(0, 10), "| proven DLL entry: cd_john_main / cd_john_version");
console.log("In-process execution remains owner-verified territory: the FFI track owns recovery_worker.rs/embedded_john wiring.");

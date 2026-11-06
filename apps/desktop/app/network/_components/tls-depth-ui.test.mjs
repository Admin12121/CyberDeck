import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import path from "node:path";

// TLS hello depth slice — source contracts. The Rust tables and the
// protocol.rs integration are the deliverables; these assertions pin what
// the UI inherits: IANA names for the common suites/extensions/groups/
// signature algorithms, honest raw-code and "not decoded" fallbacks, hard
// caps on every emitted list, and a depth pass that refuses exactly what the
// bounded hello walk refuses.

const repoRoot = path.join(import.meta.dirname, "..", "..", "..", "..", "..");
const tlsDepthSource = fs.readFileSync(
  path.join(repoRoot, "crates", "packet", "src", "domain", "dissection", "tls_depth.rs"),
  "utf8",
);
const protocolSource = fs.readFileSync(
  path.join(repoRoot, "crates", "packet", "src", "domain", "dissection", "protocol.rs"),
  "utf8",
);

test("tls_depth.rs exposes the bounded hello_depth entry point and inventory", () => {
  assert.match(tlsDepthSource, /pub fn hello_depth\(data: &\[u8\]\) -> Option<TlsDepth>/);
  assert.match(tlsDepthSource, /pub struct TlsDepth/);
  assert.match(tlsDepthSource, /pub cipher_name: Option<String>/);
  assert.match(tlsDepthSource, /pub extensions: Vec<String>/);
  assert.match(tlsDepthSource, /pub supported_versions: Vec<String>/);
  assert.match(tlsDepthSource, /pub key_share_groups: Vec<String>/);
  assert.match(tlsDepthSource, /pub signature_algorithms: Vec<String>/);
});

test("cipher suite table covers the TLS 1.3 suites and the classic IANA set", () => {
  assert.match(tlsDepthSource, /0x1301 => "TLS_AES_128_GCM_SHA256"/);
  assert.match(tlsDepthSource, /0x1302 => "TLS_AES_256_GCM_SHA384"/);
  assert.match(tlsDepthSource, /0x1303 => "TLS_CHACHA20_POLY1305_SHA256"/);
  assert.match(tlsDepthSource, /0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA"/);
  assert.match(tlsDepthSource, /0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA"/);
  assert.match(tlsDepthSource, /0xC013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"/);
  assert.match(tlsDepthSource, /0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"/);
  assert.match(tlsDepthSource, /0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"/);
  assert.match(tlsDepthSource, /0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"/);
  assert.match(tlsDepthSource, /0xCCA8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"/);
  assert.match(tlsDepthSource, /0x00FF => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"/);
});

test("unknown suites and signature algorithms degrade to the raw hex code", () => {
  // One hex fallback in cipher_suite_name, one in signature_algorithm_name —
  // never an invented name.
  const hexFallbacks = tlsDepthSource.match(/_ => format!\("0x\{code:04x\}"\)/g) || [];
  assert.ok(hexFallbacks.length >= 2, "cipher and signature tables need hex fallbacks");
});

test("extension inventory covers the documented IANA set with honest fallback", () => {
  assert.match(tlsDepthSource, /0 => "server_name"/);
  assert.match(tlsDepthSource, /10 => "supported_groups"/);
  assert.match(tlsDepthSource, /11 => "ec_point_formats"/);
  assert.match(tlsDepthSource, /13 => "signature_algorithms"/);
  assert.match(tlsDepthSource, /16 => "alpn"/);
  assert.match(tlsDepthSource, /22 => "encrypt_then_mac"/);
  assert.match(tlsDepthSource, /23 => "extended_master_secret"/);
  assert.match(tlsDepthSource, /35 => "session_ticket"/);
  assert.match(tlsDepthSource, /41 => "pre_shared_key"/);
  assert.match(tlsDepthSource, /42 => "early_data"/);
  assert.match(tlsDepthSource, /43 => "supported_versions"/);
  assert.match(tlsDepthSource, /51 => "key_share"/);
  assert.match(tlsDepthSource, /65281 => "renegotiation_info"/);
  assert.match(tlsDepthSource, /_ => format!\("extension \{code\}"\)/);
});

test("named groups cover the ECP curves, x25519/x448 and the ffdhe set", () => {
  assert.match(tlsDepthSource, /23 => "secp256r1"/);
  assert.match(tlsDepthSource, /24 => "secp384r1"/);
  assert.match(tlsDepthSource, /25 => "secp521r1"/);
  assert.match(tlsDepthSource, /29 => "x25519"/);
  assert.match(tlsDepthSource, /30 => "x448"/);
  assert.match(tlsDepthSource, /256 => "ffdhe2048"/);
  assert.match(tlsDepthSource, /257 => "ffdhe3072"/);
  assert.match(tlsDepthSource, /258 => "ffdhe4096"/);
  assert.match(tlsDepthSource, /259 => "ffdhe6144"/);
  assert.match(tlsDepthSource, /260 => "ffdhe8192"/);
  assert.match(tlsDepthSource, /_ => format!\("group \{code\}"\)/);
});

test("signature algorithm table covers the TLS 1.3 set", () => {
  assert.match(tlsDepthSource, /0x0403 => "ecdsa_secp256r1_sha256"/);
  assert.match(tlsDepthSource, /0x0401 => "rsa_pkcs1_sha256"/);
  assert.match(tlsDepthSource, /0x0804 => "rsa_pss_rsae_sha256"/);
  assert.match(tlsDepthSource, /0x0805 => "rsa_pss_rsae_sha384"/);
  assert.match(tlsDepthSource, /0x0806 => "rsa_pss_rsae_sha512"/);
});

test("every depth list is capped and truncation is reported, never silent", () => {
  assert.match(tlsDepthSource, /const MAX_LISTED_EXTENSIONS: usize = 24;/);
  assert.match(tlsDepthSource, /const MAX_LISTED_VERSIONS: usize = 8;/);
  assert.match(tlsDepthSource, /const MAX_LISTED_GROUPS: usize = 8;/);
  assert.match(tlsDepthSource, /const MAX_LISTED_SIGALGS: usize = 8;/);
  assert.match(tlsDepthSource, /list\.push\(format!\("\+\{overflow\} more \(cap \{cap\}\)"\)\)/);
});

test("uninterpretable extension bodies degrade to an explicit marker", () => {
  assert.match(tlsDepthSource, /const NOT_DECODED: &str = "not decoded \(malformed body\)";/);
  // A ClientHello offers no single suite, so none is claimed for it.
  assert.match(tlsDepthSource, /A ClientHello only offers a/);
  assert.match(tlsDepthSource, /list of suites, so no single suite is claimed for it/);
});

test("hello_depth inherits the bounded hello walk's acceptance discipline", () => {
  // Whatever tls_hello refuses (framing, bounds, malformed SNI/ALPN/versions)
  // yields no depth rather than a partial claim.
  assert.match(tlsDepthSource, /let hello = super::protocol::tls_hello\(data\)\?;/);
  assert.match(tlsDepthSource, /const MAX_TLS_RECORD: usize = 18_432;/);
  // The HelloRetryRequest form names the bare selected group.
  assert.match(tlsDepthSource, /HelloRetryRequest carries a bare selected group/);
});

test("protocol.rs integration: the description gains the depth suffix", () => {
  // TlsHello carries the captured record so the description can re-walk it.
  assert.match(protocolSource, /pub payload: Vec<u8>/);
  assert.match(protocolSource, /payload: data\[\.\.record_len \+ 5\]\.to_vec\(\)/);
  // transport.rs stays untouched: extending tls_description's output flows
  // to the wire automatically.
  assert.match(protocolSource, /let depth = super::tls_depth::hello_depth\(&tls\.payload\);/);
  assert.match(protocolSource, /Some\(name\) => value\.push_str\(&format!\(" cipher=\{name\}"\)\)/);
  assert.match(protocolSource, /value\.push_str\(" ext="\);/);
});

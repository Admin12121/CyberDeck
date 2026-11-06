import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import path from "node:path";

// HPACK (RFC 7541) slice — source contracts. The Rust decoder and its
// http2.rs integration are the deliverables; these assertions pin the
// honesty rules the UI inherits: real header names/values from the static
// table, dynamic-table state never guessed, Huffman strings never overclaimed,
// and every bound refusing with a typed error.

const repoRoot = path.join(import.meta.dirname, "..", "..", "..", "..", "..");
const hpackSource = fs.readFileSync(path.join(repoRoot, "crates", "packet", "src", "hpack.rs"), "utf8");
const http2Source = fs.readFileSync(path.join(repoRoot, "crates", "packet", "src", "domain", "dissection", "http2.rs"), "utf8");

test("hpack.rs exposes the bounded decode_header_block entry point", () => {
  assert.match(hpackSource, /pub fn decode_header_block\(\s*block: &\[u8\],\s*max_headers: usize,\s*\) -> Result<Vec<\(String, String\)>, HpackError>/);
  assert.match(hpackSource, /pub enum HpackError/);
  assert.match(hpackSource, /impl std::error::Error for HpackError/);
});

test("static table covers all 61 RFC 7541 Appendix A entries", () => {
  assert.match(hpackSource, /const STATIC_TABLE: \[\(&str, &str\); 61\]/);
  assert.match(hpackSource, /\(":method", "GET"\)/);
  assert.match(hpackSource, /\(":method", "POST"\)/);
  assert.match(hpackSource, /\(":path", "\/index\.html"\)/);
  assert.match(hpackSource, /\(":scheme", "https"\)/);
  assert.match(hpackSource, /\(":status", "200"\)/);
  assert.match(hpackSource, /\(":status", "500"\)/);
  assert.match(hpackSource, /\("accept-encoding", "gzip, deflate"\)/);
  assert.match(hpackSource, /\("www-authenticate", ""\)/);
});

test("dynamic-table references degrade honestly, never guessed", () => {
  assert.match(hpackSource, /dynamic table entry \{index\} \(state unavailable\)/);
  assert.match(hpackSource, /dynamic table entry \{index\} \(state unavailable\)"/);
  // The unavailable marker must appear as the indexed-refusal value too.
  assert.match(hpackSource, /"\(state unavailable\)"/);
});

test("Huffman strings are never decoded or overclaimed", () => {
  assert.match(hpackSource, /pub const HUFFMAN_PLACEHOLDER: &str = "<Huffman-encoded \(not decoded\)>";/);
  // The placeholder is what a Huffman literal becomes — no claimed decoding.
  assert.match(hpackSource, /RawString::Huffman => HUFFMAN_PLACEHOLDER\.to_owned\(\)/);
});

test("bounds are explicit constants and refuse with typed errors", () => {
  assert.match(hpackSource, /pub const MAX_HEADERS: usize = 32;/);
  assert.match(hpackSource, /pub const MAX_NAME_BYTES: usize = 256;/);
  assert.match(hpackSource, /pub const MAX_VALUE_BYTES: usize = 256;/);
  assert.match(hpackSource, /pub const MAX_BLOCK_BYTES: usize = 4096;/);
  assert.match(hpackSource, /BlockTooLarge \{ size: usize, max: usize \}/);
  assert.match(hpackSource, /TooManyHeaders \{ max: usize \}/);
  assert.match(hpackSource, /StringTooLong/);
  assert.match(hpackSource, /Truncated \{ detail: &'static str, at: usize \}/);
  assert.match(hpackSource, /InvalidIndex \{ index: u64 \}/);
});

test("RFC 7541 Appendix C test cases are present in hpack.rs", () => {
  assert.match(hpackSource, /fn c1_integer_encoding_small_value_uses_prefix_only/);
  assert.match(hpackSource, /fn c1_integer_encoding_1337_with_continuations/);
  assert.match(hpackSource, /fn c2_plain_string_literal_decodes_verbatim/);
  assert.match(hpackSource, /fn c2_huffman_string_degrades_to_explicit_placeholder/);
  assert.match(hpackSource, /fn c3_indexed_static_field_decodes_from_static_table/);
  assert.match(hpackSource, /fn c3_c4_literal_custom_header_decodes/);
  assert.match(hpackSource, /fn truncated_blocks_are_refused_with_typed_errors/);
});

test("http2.rs integrates HEADERS decoding at the frame loop", () => {
  // The integration point: HEADERS frames hand their body to push_header_layers.
  assert.match(http2Source, /const FRAME_TYPE_HEADERS: u8 = 1;/);
  assert.match(http2Source, /if type_byte == FRAME_TYPE_HEADERS \{/);
  assert.match(http2Source, /push_header_layers\(body, flags, &mut layers\);/);
  assert.match(http2Source, /crate::hpack::decode_header_block\(block, MAX_DECODED_HEADERS\)/);
});

test("PADDED and PRIORITY flag framing is validated before stripping", () => {
  assert.match(http2Source, /const FLAG_PADDED: u8 = 0x08;/);
  assert.match(http2Source, /const FLAG_PRIORITY: u8 = 0x20;/);
  assert.match(http2Source, /fn hpack_block\(body: &\[u8\], flags: u8\) -> Result<&\[u8\], &'static str>/);
  assert.match(http2Source, /PADDED pad length exceeds the frame body/);
  assert.match(http2Source, /PRIORITY flag set but the frame body is shorter than 5 priority bytes/);
});

test("per-header layers are capped and values display-truncated", () => {
  assert.match(http2Source, /const MAX_DECODED_HEADERS: usize = 8;/);
  assert.match(http2Source, /const MAX_VALUE_DISPLAY_CHARS: usize = 128;/);
  assert.match(http2Source, /label: "HTTP\/2 header"/);
  assert.match(http2Source, /fn display_value\(value: &str\) -> String/);
});

test("decode failures degrade to one honest error layer, never dropped frames", () => {
  assert.match(http2Source, /label: "HTTP\/2 headers"/);
  assert.match(http2Source, /HPACK decode failed: \{err\}/);
  assert.match(http2Source, /HPACK block unavailable: \{reason\}/);
});

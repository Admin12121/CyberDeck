import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import path from "node:path";
import { protocolHierarchy } from "./model/index.ts";

const root = import.meta.dirname;
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const packetSrc = path.join(root, "../../../../../crates/packet/src");
const quicRs = fs.readFileSync(path.join(packetSrc, "domain/dissection/quic.rs"), "utf8");
const http2Rs = fs.readFileSync(path.join(packetSrc, "domain/dissection/http2.rs"), "utf8");
const transportRs = fs.readFileSync(path.join(packetSrc, "domain/dissection/transport.rs"), "utf8");
const model = read("model/index.ts");

test("QUIC rows state the protected payload plainly and never claim names or contents", () => {
  assert.match(quicRs, /"QUIC protected payload"/);
  assert.match(quicRs, /byte\(s\), keys unavailable/);
  // The dissector has no header-protection keys: SNI, server names and
  // decrypted frame contents must never appear in any emitted value. Match
  // against the non-test, comment-stripped code so the "no SNI" promise in
  // the docs and the dissector's own negative test do not count as claims.
  const quicBody = quicRs.slice(0, quicRs.indexOf("#[cfg(test)]"));
  const quicCode = quicBody.replace(/\/\/[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
  assert.doesNotMatch(quicCode, /sni|server name/i);
  assert.doesNotMatch(quicCode, /decrypt/);
  // Short headers are exactly the honest sentence, nothing more.
  assert.match(quicRs, /QUIC short header \(1-RTT\); DCID not recoverable without prior state/);
});

test("QUIC bounds are real: 20-byte connection IDs, bounded hex, bounded varints", () => {
  assert.match(quicRs, /const MAX_CONNECTION_ID: usize = 20/);
  assert.match(quicRs, /exceeds the \{MAX_CONNECTION_ID\}-byte QUIC limit; refused/);
  assert.match(quicRs, /DCID truncated/);
  assert.match(quicRs, /fn hex_bounded/);
  assert.match(quicRs, /fn varint/);
  // Every refusal degrades to an honest QUIC row, never a bare truncation
  // mislabel, and the module has fixtures proving it.
  assert.match(quicRs, /oversized_or_truncated_dcids_degrade_honestly_not_panic/);
});

test("HTTP/2 detection is prior-knowledge only and frame parsing stays bounded", () => {
  assert.match(http2Rs, /b"PRI \* HTTP\/2\.0\\r\\n\\r\\nSM\\r\\n\\r\\n"/);
  assert.match(http2Rs, /const MAX_FRAMES_PARSED: usize = 4/);
  assert.match(http2Rs, /& 0x7f/); // reserved high bit of the stream id is masked
  assert.match(http2Rs, /truncated at capture boundary/);
  assert.match(http2Rs, /pub fn dissect_http2\(/);
});

test("transport hooks: QUIC on UDP/443 after length validation, HTTP/2 before start-line guessing", () => {
  assert.match(transportRs, /src_port == 443 \|\| dst_port == 443/);
  assert.match(transportRs, /quic::dissect_quic\(&payload, layers\)/);
  const lengthBound = transportRs.indexOf("let payload = transport.get(8..end)");
  const quicHook = transportRs.indexOf("quic::dissect_quic(&payload, layers)");
  const http2Hook = transportRs.indexOf("is_http2_preface(&payload)");
  const startLine = transportRs.indexOf("protocol::http_start_line(&payload)");
  assert.ok(lengthBound !== -1, "UDP payload must be bounded by the declared length");
  assert.ok(quicHook !== -1, "QUIC dispatch hook missing from dissect_udp");
  assert.ok(lengthBound < quicHook, "QUIC dispatch must follow the UDP length checks so padding never becomes QUIC fields");
  assert.ok(http2Hook !== -1 && startLine !== -1 && http2Hook < startLine, "HTTP/2 preface check must precede the HTTP/1 start-line check");
  // QUIC rows keep their UDP evidence layers like DNS/STUN rows do.
  assert.match(transportRs, /label: "User Datagram Protocol"/);
});

test("model hierarchy leaf branch carries quic and http2 without special-casing", () => {
  // The exclusion list is exactly these six names; quic and http2 pass
  // through the fall-through leaf push.
  assert.match(model, /!\["tcp", "udp", "ip", "ipv6", "icmp", "icmpv6"\]\.includes\(leaf\)/);
  assert.doesNotMatch(model, /"quic"|"http2"/);

  // Functional check with the layer labels the Rust dissectors actually emit.
  const quicRow = {
    source: "10.0.0.1", destination: "10.0.0.2", protocol: "QUIC",
    info: "QUIC Initial, DCID aabbccdd, 8 protected byte(s)", length: 1252,
    layers: [
      { label: "Internet Protocol Version 4", value: "10.0.0.1 → 10.0.0.2" },
      { label: "User Datagram Protocol", value: "443 → 51000 Len=1232" },
    ],
  };
  const http2Row = {
    source: "10.0.0.1", destination: "10.0.0.2", protocol: "HTTP2",
    info: "HTTP/2 connection preface, SETTINGS(s0)", length: 47,
    layers: [{ label: "Internet Protocol Version 4", value: "10.0.0.1 → 10.0.0.2" }],
  };
  const hierarchy = protocolHierarchy([quicRow, http2Row]);
  const ip = hierarchy.find((n) => n.protocol === "ip");
  assert.ok(ip, "both rows dissect through IPv4, so ip is the root");
  const udp = ip.children.find((n) => n.protocol === "udp");
  assert.ok(udp && udp.children.some((n) => n.protocol === "quic" && n.packets === 1),
    "QUIC must appear as a leaf under udp via the User Datagram Protocol layer label");
  assert.ok(ip.children.some((n) => n.protocol === "http2" && n.packets === 1),
    "HTTP2 must appear as an ip leaf (prior-knowledge rows carry no TCP detail layers)");
});

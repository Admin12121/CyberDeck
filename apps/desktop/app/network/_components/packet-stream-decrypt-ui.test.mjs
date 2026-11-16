import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import path from "node:path";

const root = import.meta.dirname;
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");

test("TLS 1.3 keylog card exists with centered import affordance and honest default state", () => {
  const studio = read("PacketStudioView.tsx");
  // The card lives in the streams tab; no case management, no mode buttons.
  assert.match(studio, /<TlsKeylogCard/);
  assert.match(studio, /function TlsKeylogCard/);
  assert.match(studio, /StreamsTabWithKeylog/);
  // Centered card region with at most one border and no ALL-CAPS headers.
  assert.match(studio, /justify-center border-b border-line bg-panel/);
  assert.doesNotMatch(studio, /TLS 1\.3 KEYLOG|KEYLOG IMPORT/);
  // ONE-line description + InfoTip; no multi-paragraph prose on screen.
  assert.match(studio, /<InfoTip text=/);
  assert.match(studio, /keylogCardLine\(status\)/);
});

test("no decryption claim without an imported keylog", () => {
  const client = read("packet-stream-keylog-ipc.ts");
  const studio = read("PacketStudioView.tsx");
  // The honest default line explicitly denies decryption.
  assert.match(
    client,
    /none imported; stream transcripts stay ciphertext/,
  );
  // The card line helper is the single source of the one-liner.
  assert.match(studio, /keylogCardLine\(status\)/);
  // Decrypted content is rendered only for chunks the BACKEND marked,
  // never invented in the UI layer.
  assert.match(studio, /\(chunk\.kind as string\) === "decrypted" \? "\[decrypted\] " : ""/);
  // Import and clear go through the named IPC wrappers only.
  assert.match(studio, /packetStreamKeylogAttachV1\(/);
  assert.match(studio, /packetStreamKeylogClearV1\(/);
  assert.match(studio, /packetStreamKeylogStatusV1\(/);
});

test("keylog IPC client uses the documented v1 command names", () => {
  const client = read("packet-stream-keylog-ipc.ts");
  assert.match(client, /invoke<KeylogStatusWire>\("packet_stream_keylog_attach_v1"/);
  assert.match(client, /invoke<KeylogStatusWire>\("packet_stream_keylog_status_v1"/);
  assert.match(client, /invoke<KeylogStatusWire>\("packet_stream_keylog_clear_v1"/);
  // No keylog bytes cross the wire: the status wire carries counts only.
  assert.doesNotMatch(client, /secrets:|secret_hex|client_handshake|server_handshake/);
});

test("keylog imports open the native dialog on the Rust side, not in the UI", () => {
  const client = read("packet-stream-keylog-ipc.ts");
  // The attach command takes no path argument: the dialog opens natively.
  assert.match(client, /invoke<KeylogStatusWire>\("packet_stream_keylog_attach_v1", \{\}\)/);
  assert.doesNotMatch(client, /path:|filePath/);
});

test("stream transcripts re-fetch when the keylog attachment changes", () => {
  const studio = read("PacketStudioView.tsx");
  assert.match(studio, /keylogVersion/);
  assert.match(studio, /\[selected, packets, artifactId, keylogVersion\]/);
  // Decrypted hex is sendable to Recipes like plaintext data.
  assert.match(
    studio,
    /chunk\.kind === "datagram" \|\| \(chunk\.kind as string\) === "decrypted"/,
  );
});

test("TLS 1.2 CLIENT_RANDOM master secrets ride the same keylog surface", () => {
  const client = read("packet-stream-keylog-ipc.ts");
  const studio = read("PacketStudioView.tsx");
  // Since the TLS 1.2 slice, the Rust keylog parser retains CLIENT_RANDOM
  // lines (the master secret) alongside the TLS 1.3 traffic secrets. Label
  // acceptance lives entirely in that parser: the IPC layer filters and
  // renames no labels, and no keylog bytes cross the wire.
  assert.doesNotMatch(client, /CLIENT_RANDOM|CLIENT_EARLY|TRAFFIC_SECRET_0/);
  // `entries` keeps counting TLS 1.3 traffic secrets only; the connection
  // count covers every ClientHello random the keylog binds, TLS 1.2 and
  // TLS 1.3 alike.
  assert.match(client, /Accepted TLS 1\.3 traffic-secret entries/);
  assert.match(client, /status\.connections}/);
  // Backend-marked "decrypted" chunks render with no TLS-version gate in
  // the UI layer — the same emission contract the TLS 1.2 path uses.
  assert.match(studio, /\(chunk\.kind as string\) === "decrypted" \? "\[decrypted\] " : ""/);
  assert.match(
    studio,
    /chunk\.kind === "datagram" \|\| \(chunk\.kind as string\) === "decrypted"/,
  );
});

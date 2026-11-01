import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import path from "node:path";
import { matchesFilter, protocolStats } from "./model/index.ts";

const source = fs.readFileSync(path.join(import.meta.dirname, "PacketStudioView.tsx"), "utf8");

test("Statistics protocol actions populate display filter and open Packets", () => {
  assert.match(source, /const inspectProtocol = \(protocol: string\) => \{/);
  assert.match(source, /setFilter\(protocol\.toLowerCase\(\)\)/);
  assert.match(source, /setTab\("packets"\)/);
  assert.match(source, /onClick=\{\(\) => inspectProtocol\(stat\.protocol\)\}/);
  assert.match(source, /aria-label=\{\x60Show \$\{stat\.protocol\} packets\x60\}/);
});

test("Stats protocol filters select actual dissected packets across protocol names", () => {
  const packets = [
    { source: "192.0.2.1", destination: "192.0.2.2", protocol: "HTTP", info: "GET /", length: 128, layers: [] },
    { source: "192.0.2.1", destination: "192.0.2.2", protocol: "TLSv1.3", info: "Application Data", length: 350, layers: [] },
    { source: "192.0.2.2", destination: "192.0.2.1", protocol: "SSH", info: "Key exchange", length: 214, layers: [] },
    { source: "192.0.2.2", destination: "192.0.2.1", protocol: "TCP", info: "ACK", length: 66, layers: [] },
  ];
  for (const stat of protocolStats(packets)) {
    const result = packets.filter((packet) => matchesFilter(packet, stat.protocol.toLowerCase()));
    assert.equal(result.length, stat.packets);
    assert.ok(result.every((packet) => packet.protocol === stat.protocol));
  }
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { nativeCapturePacketRow } from "./packet-row-model.ts";

test("native frame rows preserve only backend-owned provenance", () => {
  const row = nativeCapturePacketRow({
    packet_index: 5, pcap_frame_offset: 248, captured_length: 96,
    wire_length: 102, source: "192.0.2.1", destination: "198.51.100.2",
    stream_id: null,
  });
  assert.equal(row.index, 5);
  assert.equal(row.length, 96);
  assert.equal(row.source, "192.0.2.1");
  assert.equal(row.destination, "198.51.100.2");
  assert.match(row.info, /248/);
  assert.equal(row.protocol, null);
  assert.equal(row.time, undefined);
});

test("stream ID appears only when backend supplied it", () => {
  const row = nativeCapturePacketRow({
    packet_index: 0, pcap_frame_offset: 24, captured_length: 60,
    wire_length: 60, source: null, destination: null,
    stream_id: "tcp:2001:db8::1:80>2001:db8::2:8443",
  });
  assert.match(row.info, /tcp:2001:db8::1:80/);
  assert.equal(row.source, null);
  assert.equal(row.protocol, null);
});

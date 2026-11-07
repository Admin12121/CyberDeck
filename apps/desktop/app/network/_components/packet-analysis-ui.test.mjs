import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import path from "node:path";

const root = import.meta.dirname;
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");

test("Packet Analysis starts with one welcome workflow, not two mode buttons", () => {
  const studio = read("PacketStudioView.tsx");
  const start = read("PacketStartView.tsx");
  assert.doesNotMatch(studio, /Opened PCAP \/ Sample|Native Live Capture/);
  assert.match(studio, /screen === "welcome"/);
  assert.match(studio, /<PacketStartView/);
  assert.match(start, /Capture file/);
  assert.match(start, /Recent/);
  assert.doesNotMatch(start, /Sample/);
  assert.match(start, /No recent captures/);
  assert.doesNotMatch(start, /mock recent|mock file/i);
});

test("native discovery, capture and Stop are reused without new backend commands", () => {
  const studio = read("PacketStudioView.tsx");
  const live = read("LiveCaptureView.tsx");
  assert.match(live, /captureInterfacesV1\(/);
  assert.match(live, /captureStartV1\(/);
  assert.match(live, /captureStopV1\(/);
  assert.match(live, /captureStatusV1\(/);
  assert.match(live, /captureProvenanceV1\(/);
  assert.match(live, /currentNativeSession\(/);
  assert.match(live, /rememberNativeSession\(/);
  assert.match(live, /presentation === "setup"/);
  assert.match(live, /entry\.up && entry\.ethernet && !entry\.loopback/);
  assert.match(live, /onCaptureStarted\?\.\(\)/);
  assert.match(live, /onReturnToStart/);
  assert.match(studio, /pcapOpenDialog\(/);
  assert.match(studio, /pcapPacketBytes\(/);
  assert.match(studio, /pcapFollowStream\(/);
});

test("native capture retains original provenance, authorized save and parsed packet details", () => {
  const start = read("PacketStartView.tsx");
  const live = read("LiveCaptureView.tsx");
  const studio = read("PacketStudioView.tsx");
  assert.match(live, /Native capture/);
  assert.match(live, /Original captured frame/);
  assert.match(live, /captureSaveV1\(/);
  assert.match(live, /Save Capture to Case/);
  assert.match(live, /useCaseReady\(\)/);
  assert.doesNotMatch(start, /Demonstration packets/);
  assert.match(studio, /DEMO: sample packets/);
  assert.match(studio, /Send to Recipes/);
});

test("shared tabs use coss Tabs, TabsList, TabsTab and optional TabsPanel, not underline", () => {
  const panes = fs.readFileSync(path.join(root, "../../../design-system/panes.tsx"), "utf8");
  assert.match(panes, /import \{ Tabs, TabsList, TabsPanel, TabsTab \}/);
  assert.match(panes, /<Tabs\b/);
  assert.match(panes, /<TabsList\b/);
  assert.match(panes, /<TabsTab\b/);
  assert.match(panes, /<TabsPanel\b/);
  assert.doesNotMatch(panes, /variant="underline"/);
});

test("opened files and native capture share one packet list presentation", () => {
  const offline = read("PacketStudioView.tsx");
  const native = read("LiveCaptureView.tsx");
  const shared = read("PacketTable.tsx");
  assert.match(offline, /<PacketTable/);
  assert.match(native, /<PacketTable/);
  assert.match(shared, /Packet list/);
  assert.match(shared, /Protocol/);
  assert.match(native, /Original captured frame/);
  assert.match(native, /Packet details:/);
  assert.match(native, /Packet bytes \(offset/);
  assert.match(native, /Frame inspection available once capture completes/);
  assert.match(native, /capturePacketDetailsV1\(/);
  assert.match(native, /decoded\.layers\.map/);
  assert.match(native, /<WorkspaceTabs items=\{\["packets", "hosts", "flows", "statistics"\]/);
});

test("welcome keeps live capture setup below file opening without duplicated mode buttons", () => {
  const studio = read("PacketStudioView.tsx");
  const start = read("PacketStartView.tsx");
  assert.match(studio, /mt-auto shrink-0 pt-2/);
  assert.match(start, /Packet Analysis/);
  assert.match(start, /Capture file/);
  assert.doesNotMatch(studio, /Opened PCAP \/ Sample|Native Live Capture/);
});

test("start screen is aligned, succinct and capture settings are progressive", () => {
  const start = read("PacketStartView.tsx");
  const capture = read("LiveCaptureView.tsx");
  const studio = read("PacketStudioView.tsx");
  assert.match(start, /w-full shrink-0 px-5 pt-5/);
  assert.doesNotMatch(start, /mx-auto w-full max-w-6xl/);
  assert.doesNotMatch(start, /Previously opened files are not retained/);
  assert.match(capture, /const \[showLimits, setShowLimits\]/);
  assert.match(capture, /showLimits && desktop/);
  assert.match(capture, /aria-expanded=\{showLimits\}/);
  assert.match(capture, /Saved case required/);
  assert.match(capture, /Live capture requires the desktop application/);
  assert.match(capture, /<Button key=\{entry.index/);
  assert.match(capture, /aria-pressed=\{selected\}/);
  assert.match(studio, /const rowHeight = 26/);
});

test("packet table remains one shared readable style for real and native packets", () => {
  const table = read("PacketTable.tsx");
  const style = fs.readFileSync(path.join(root, "../../../app/globals.css"), "utf8");
  assert.match(table, /cd-packet-table/);
  assert.match(table, /h-\[26px\]/);
  assert.match(style, /\.cd-packet-table th/);
  assert.match(style, /\.cd-packet-table td/);
});

test("Capture starts from clicking a real eligible interface, with native authorization unchanged", () => {
  const live = read("LiveCaptureView.tsx");
  const welcome = read("PacketStartView.tsx");
  assert.match(live, /onClick=\{\(\) => \{ setDevice\(entry.name\); void start\(entry.name\); \}\}/);
  assert.match(live, /async function start\(selectedDevice = device\)/);
  assert.match(live, /eligible\.some\(\(entry\) => entry\.name === selectedDevice\)/);
  assert.match(live, /captureStartV1\(selectedDevice, limits, captureFilter/);
  assert.match(live, /Select an authorized saved case/);
  assert.match(live, /<Router\b/);
  assert.doesNotMatch(live, /rounded-md border border-line bg-panel px-4 py-5 text-sm/);
  assert.doesNotMatch(welcome, /onSample|Load Sample/);
});

test("shared packet inspectors support vertical and unconstrained responsive horizontal dragging", () => {
  const split = read("PacketPaneSplit.tsx");
  const offline = read("PacketStudioView.tsx");
  const live = read("LiveCaptureView.tsx");
  for (const source of [offline, live]) assert.match(source, /<PacketPaneSplit/);
  assert.match(split, /<Resizer direction="vertical"/);
  assert.match(split, /<Resizer direction="horizontal"/);
  assert.match(split, /new ResizeObserver/);
  assert.match(split, /bounds\.width - 180/);
  assert.match(split, /bounds\.height - 132/);
  assert.match(split, /Show Inspectors/);
  assert.match(split, /Hide packet details/);
  assert.match(split, /Hide packet bytes/);
  assert.doesNotMatch(split, /max=\{720\}/);
});

test("capture sparkline is based only on real native packet counter updates", () => {
  const live = read("LiveCaptureView.tsx");
  const graph = read("CaptureActivity.tsx");
  assert.match(live, /captureStatusV1\(id\)/);
  assert.match(live, /setActivity\(\(history\) => \[\.\.\.history, \{ at: Date\.now\(\), packets: next\.progress\.packets \}\]/);
  assert.match(live, /<CaptureActivity samples=\{activity\}/);
  assert.match(graph, /item\.packets - previous\.packets/);
  assert.match(graph, /samples\.length < 2/);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import path from "node:path";

const base = import.meta.dirname;
const read = (filename) => fs.readFileSync(path.join(base, filename), "utf8");
const proxy = read("ProxyView.tsx");
const workspace = read("WebWorkspace.tsx");
const certificate = read("ProxyCertificateAction.tsx");

test("the sole Proxy CA download action belongs in the top-right workspace tab header, not the card", () => {
  assert.match(workspace, /<WorkspaceTabs\b/);
  assert.match(workspace, /absolute inset-y-0 right-2 z-10/);
  assert.match(workspace, /tab === "proxy"/);
  assert.match(workspace, /<ProxyCertificateAction\s*\/>/);
  assert.doesNotMatch(proxy, /<Download\b|aria-label="Download proxy CA certificate"|saveCa\(/);
  assert.equal((certificate.match(/<Download\b/g) ?? []).length, 1);
  assert.match(certificate, /aria-label="Download proxy CA certificate"/);
  assert.match(certificate, /const pem = await proxyCaPem\(\)/);
  assert.match(certificate, /downloadContent\(pem, "cyberdeck-root-ca\.crt"/);
  assert.match(certificate, /disabled=\{!desktop \|\| exporting\}/);
});

test("Proxy Frame is centered and uses coss Frame > FrameHeader > FramePanel hierarchy", () => {
  assert.match(proxy, /import \{ Frame, FrameHeader, FramePanel, FrameTitle \}/);
  assert.match(proxy, /flex min-h-full w-full items-center justify-center/);
  assert.match(proxy, /<Frame className="mx-auto w-full max-w-2xl/);
  assert.match(proxy, /<FrameHeader\b/);
  assert.match(proxy, /<FrameTitle>Local interception proxy<\/FrameTitle>/);
  assert.match(proxy, /<FramePanel\b/);
  assert.ok(proxy.indexOf("<FrameHeader") < proxy.indexOf("<FramePanel"));
  assert.ok(proxy.indexOf("</FramePanel>") < proxy.indexOf("</Frame>"));
});

test("Proxy default display is focused; optional advanced preserves security and rules", () => {
  assert.match(proxy, /\{advancedOpen && \(/);
  assert.match(proxy, /aria-expanded=\{advancedOpen\}/);
  assert.doesNotMatch(proxy, /Case-bound volatile capture consent|Match & replace \(|HTTP\(S\) and WebSocket behavior varies/);
  assert.match(proxy, /webCaptureConsentStartV1\(/);
  assert.match(proxy, /webCaptureConsentRevokeV1\(/);
  assert.match(proxy, /proxySetRules\(/);
  assert.match(proxy, /proxyIntercept\(/);
  assert.match(proxy, /proxyForward\(/);
  assert.match(proxy, /proxyDrop\(/);
});

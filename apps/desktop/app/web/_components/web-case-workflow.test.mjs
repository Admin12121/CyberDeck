import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import path from "node:path";

const base = import.meta.dirname;
const read = (name) => fs.readFileSync(path.join(base, name), "utf8");
const scanner = read("ScannerView.tsx");
const spider = read("SpiderView.tsx");
const repeater = read("RepeaterView.tsx");
const proxy = read("ProxyView.tsx");
const history = read("HistoryView.tsx");
const jobs = read("../../../src-tauri/src/features/web/application/assessment_jobs.rs");

test("Web scanner requires backend-selected saved case and exposes a clear way to create one", () => {
  assert.match(scanner, /caseSession\.phase === "ready"/);
  assert.match(scanner, /<AuthorizedCaseAction activity="Web security assessment"/);
  assert.match(scanner, /disabled=\{!desktop \|\| !caseReady \|\| !normalized \|\| !authorized \|\| running\}/);
  assert.match(scanner, /\{advancedOpen && \(/);
  assert.match(scanner, /setJobId\(null\)/);
  assert.match(scanner, /Session context enabled \(volatile\)/);
  assert.match(scanner, /setSessionCookie\(""\); setSessionHeaders\(""\)/);
  assert.match(scanner, /cancelWebAssessment\(jobId\)/);
});

test("Web Spider requires saved case and persists only explicit backend-owned discoveries", () => {
  assert.match(spider, /<AuthorizedCaseAction activity="Web site discovery"/);
  assert.match(spider, /disabled=\{busy \|\| !desktop \|\| !caseReady/);
  assert.match(spider, /saveWebAssessmentFindings\(job\.job_id\)/);
  assert.match(spider, /Save discovered routes to case/);
  assert.match(jobs, /"spider" => "web\.spider"/);
  assert.match(jobs, /state\s*\.urls\s*\.iter\(\)\s*\.take\(60\)/);
  assert.match(jobs, /parsed\.password\(\)\.is_some\(\)/);
});

test("Web Repeater drops raw drafts and response data when switching case revisions", () => {
  assert.match(repeater, /lastCaseIdentity\.current\.caseId !== caseId/);
  assert.match(repeater, /lastHandoff\.current = repeaterHandoff\?\.id \?\? 0/);
  assert.match(repeater, /setTabs\(\[\{ name: "R1", request: SAMPLE_REQUEST, response: null, error: null \}\]\)/);
  assert.match(repeater, /<AuthorizedCaseAction activity="Web request replay"/);
  assert.match(repeater, /disabled=\{busy \|\| !desktop \|\| !caseReady\}/);
});

test("Proxy/History expose saved-case consent workflow and never claim automatic CA trust", () => {
  assert.match(proxy, /<AuthorizedCaseAction activity="Private HTTP history capture"/);
  assert.match(proxy, /!caseReady \|\| !status\.running \|\| consentBusy/);
  assert.match(proxy, /does not install trust automatically/);
  assert.match(history, /<AuthorizedCaseAction activity="Private Web history"/);
  assert.match(history, /Enable case-bound capture consent|authorize private History capture in Proxy/i);
});
